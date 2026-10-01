// platform_win.c — real Windows implementations (registry via advapi32,
// service via net stop/start, GUID via UuidCreate, download via WinHTTP).
#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include "platform.h"
#include "defs.h"
#include "util.h"

#include <windows.h>
#include <rpc.h>
#include <shlobj.h>
#include <winhttp.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")

vdu_hooks plt = { 0 }; // zeroed: default implementations are used when NULL

static int reg_read_impl(const char *value, char *out, size_t outsz) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DEF_REG_KEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, cb = (DWORD)outsz;
    LONG rc = RegQueryValueExA(k, value, NULL, &type, (BYTE *)out, &cb);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return 0;
    out[cb < outsz ? cb : outsz - 1] = 0;
    return 1;
}

static int reg_write_impl(const char *av, const char *as) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DEF_REG_KEY, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    LONG r1 = RegSetValueExA(k, DEF_REG_AV, 0, REG_SZ, (const BYTE *)av, (DWORD)strlen(av) + 1);
    LONG r2 = RegSetValueExA(k, DEF_REG_AS, 0, REG_SZ, (const BYTE *)as, (DWORD)strlen(as) + 1);
    RegCloseKey(k);
    return (r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS) ? 0 : -1;
}

static int reg_dump_impl(void *file_out) {
    FILE *f = file_out;
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DEF_REG_KEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    DWORD idx = 0, subs;
    fprintf(f, "  [registry] HKLM\\%s:\n", DEF_REG_KEY);
    for (;;) {
        char name[256];
        DWORD name_len = sizeof(name), type = 0, cb = 0;
        LONG rc = RegEnumValueA(k, idx, name, &name_len, NULL, &type, NULL, &cb);
        if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) break;
        if (rc == ERROR_MORE_DATA || type != REG_SZ) {
            fprintf(f, "    %s = <type %lu, %lu bytes>\n", name, (unsigned long)type, (unsigned long)cb);
        } else {
            char *data = xmalloc(cb + 1);
            DWORD cb2 = cb;
            if (RegQueryValueExA(k, name, NULL, NULL, (BYTE *)data, &cb2) == ERROR_SUCCESS)
                fprintf(f, "    %s = %s\n", name, data);
            free(data);
        }
        idx++;
        (void)subs;
    }
    RegCloseKey(k);
    return 0;
}

static int service_installed_impl(void) {
    HKEY k;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" DEF_SERVICE,
                            0, KEY_QUERY_VALUE, &k);
    if (rc != ERROR_SUCCESS) return 0;
    RegCloseKey(k);
    return 1;
}

static int run_net(const char *verb) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "net %s " DEF_SERVICE, verb);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0 ? 0 : -1;
}

static int service_stop_impl(void)  { return run_net("stop"); }
static int service_start_impl(void) { return run_net("start"); }

static int service_running_impl(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceA(scm, DEF_SERVICE, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    SERVICE_STATUS st;
    int running = QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return running;
}

static int guid_new_impl(char *out, size_t outsz) {
    UUID u;
    if (UuidCreate(&u) != RPC_S_OK) return -1;
    RPC_CSTR str = NULL;
    if (UuidToStringA(&u, &str) != RPC_S_OK) return -1;
    snprintf(out, outsz, "{%s}", (char *)str);
    RpcStringFreeA(&str);
    return 0;
}

static int common_appdata_impl(char *out, size_t outsz) {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path) != S_OK) return -1;
    snprintf(out, outsz, "%s", path);
    return 0;
}

static int download_impl(const char *url, const char *path) {
    WCHAR wurl[2048], wpath[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 2048) == 0) return -1;
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024) == 0) return -1;

    URL_COMPONENTS uc;
    WCHAR whost[256], wreq[1024];
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = wreq;
    uc.dwUrlPathLength = 1024;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return -1;

    HINTERNET ses = WinHttpOpen(L"WDUV/" L"" APP_VERSION, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return -1;
    HINTERNET conn = WinHttpConnect(ses, whost, uc.nPort, 0);
    if (!conn) { WinHttpCloseHandle(ses); return -1; }
    HINTERNET rq = WinHttpOpenRequest(conn, L"GET", wreq, NULL, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!rq) { WinHttpCloseHandle(conn); WinHttpCloseHandle(ses); return -1; }

    // Vista's schannel tops out at TLS 1.0: modern CDNs may refuse the
    // handshake. Report it clearly instead of pretending.
    int rc = -1;
    if (WinHttpSendRequest(rq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(rq, NULL)) {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(rq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status == 200) {
            FILE *f = fopen(path, "wb");
            if (f) {
                rc = 0;
                DWORD avail = 0;
                for (;;) {
                    if (!WinHttpQueryDataAvailable(rq, &avail)) { rc = -1; break; }
                    if (!avail) break;
                    char *buf = xmalloc(avail);
                    DWORD rd = 0;
                    if (!WinHttpReadData(rq, buf, avail, &rd) || rd == 0) { free(buf); rc = -1; break; }
                    if (fwrite(buf, 1, rd, f) != rd) { free(buf); rc = -1; break; }
                    free(buf);
                }
                if (fclose(f) != 0) rc = -1;
            }
        } else {
            vdu_log("HTTP %lu for %s", (unsigned long)status, url);
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_SECURE_FAILURE)
            vdu_log("TLS handshake failed (%s on this OS likely lacks TLS 1.2) — "
                    "use 'fetch' on a modern PC and 'apply -package' on the Vista box", url);
        else
            vdu_log("WinHTTP error %lu for %s", (unsigned long)err, url);
    }
    WinHttpCloseHandle(rq);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(ses);
    return rc;
}

static int arch_impl(void) {
#if defined(_WIN64)
    return 64;
#else
    BOOL wow = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow) && wow) return 64;
    return 0;
#endif
}

// Install the default implementations into the hook table (called once).
__attribute__((constructor)) static void plt_init(void) {
    plt.reg_read = reg_read_impl;
    plt.reg_write = reg_write_impl;
    plt.reg_dump = reg_dump_impl;
    plt.service_installed = service_installed_impl;
    plt.service_stop = service_stop_impl;
    plt.service_start = service_start_impl;
    plt.service_running = service_running_impl;
    plt.guid_new = guid_new_impl;
    plt.common_appdata = common_appdata_impl;
    plt.download = download_impl;
    plt.arch = arch_impl;
}
