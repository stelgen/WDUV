// gui.c — Vista Defender-styled GUI (Win32, GDI only, wine-friendly).
// Mimics the stock Windows Defender window: blue→green banner, light
// toolbar, white content. All long operations run on a worker thread and
// report through the embedded log pane.
#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include "ops.h"
#include "status.h"
#include "util.h"

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WM_APP_LOG   (WM_APP + 1)
#define WM_APP_DONE  (WM_APP + 2)

#define IDC_UPDATE     2001
#define IDC_APPLY      2002
#define IDC_BACKUP     2003
#define IDC_ROLLBACK   2004
#define IDC_LOG        2005
#define IDC_ST_LINE1   2006
#define IDC_ST_LINE2   2007
#define IDC_ST_LINE3   2008
#define IDC_ST_LINE4   2009

#define BANNER_H   58
#define TOOLBAR_H  44

static HWND g_hwnd, g_log;
static HFONT g_font, g_font_bold, g_font_title;
static HBRUSH g_br_white, g_br_toolbar, g_br_border;
static HICON g_shield;

static void gui_log(void *ud, const char *line) {
    (void)ud;
    char *copy = xstrdup(line);
    PostMessage(g_hwnd, WM_APP_LOG, 0, (LPARAM)copy);
}

static DWORD WINAPI worker_thread(LPVOID param) {
    int op = (int)(intptr_t)param;
    int rc = 0;
    switch (op) {
    case 0: rc = vdu_ops_update(NULL, 0, 0, 0, gui_log, NULL); break;
    case 2: rc = vdu_ops_backup(gui_log, NULL); break;
    case 3: rc = vdu_ops_rollback(gui_log, NULL); break;
    }
    PostMessage(g_hwnd, WM_APP_DONE, 0, (LPARAM)(intptr_t)rc);
    return 0;
}

// op+string worker: op in [10..19], string malloc'd
struct work_item { int op; char *str; };

static DWORD WINAPI worker_thread_str(LPVOID param) {
    struct work_item *wi = (struct work_item *)param;
    int rc;
    if (wi->op == 10) {
        // update with -source
        rc = vdu_ops_update(wi->str && wi->str[0] ? wi->str : NULL, 0, 0, 0, gui_log, NULL);
    } else { // 11 = apply package
        rc = vdu_ops_apply(wi->str, 0, 0, gui_log, NULL);
    }
    free(wi->str);
    free(wi);
    PostMessage(g_hwnd, WM_APP_DONE, 0, (LPARAM)(intptr_t)rc);
    return 0;
}

static void start_str(int op, const char *str) {
    struct work_item *wi = xmalloc(sizeof(*wi));
    wi->op = op;
    wi->str = str ? xstrdup(str) : NULL;
    CreateThread(NULL, 0, worker_thread_str, wi, 0, NULL);
}

static void start_simple(int op) {
    CreateThread(NULL, 0, worker_thread, (LPVOID)(intptr_t)op, 0, NULL);
}

static void refresh_status(void) {
    vdu_status st;
    vdu_status_collect(&st);
    char l1[1200], l2[1200], l3[1200], l4[1200];
    snprintf(l1, sizeof(l1), "Windows Defender Version: 1.1.1600.0 (built-in, Vista)");
    snprintf(l2, sizeof(l2), "Engine Version: %s", st.engine_ver[0] ? st.engine_ver : "(not found)");
    snprintf(l3, sizeof(l3), "Definition Version: %s", st.def_ver[0] ? st.def_ver : "(not found)");
    snprintf(l4, sizeof(l4), "Service %s | folder %s",
             st.service_running ? "running" : (st.service_installed ? "stopped" : "not installed"),
             st.reg_as[0] ? st.reg_as : st.reg_av[0] ? st.reg_av : "-");
    SetDlgItemText(g_hwnd, IDC_ST_LINE1, l1);
    SetDlgItemText(g_hwnd, IDC_ST_LINE2, l2);
    SetDlgItemText(g_hwnd, IDC_ST_LINE3, l3);
    SetDlgItemText(g_hwnd, IDC_ST_LINE4, l4);
}

static void paint_banner(HDC hdc, HWND hwnd) {
    RECT rc, r;
    GetClientRect(hwnd, &rc);
    // horizontal gradient blue -> green across the banner
    int w = rc.right;
    for (int x = 0; x < w; x += 2) {
        double t = (double)x / (double)(w > 1 ? w - 1 : 1);
        int r0 = 0x2E + (int)((0x7C - 0x2E) * t);
        int g0 = 0x6D + (int)((0xBB - 0x6D) * t);
        int b0 = 0xA5 + (int)((0x4C - 0xA5) * t);
        RECT col = { x, 0, x + 2, BANNER_H };
        HBRUSH br = CreateSolidBrush(RGB(r0, g0, b0));
        FillRect(hdc, &col, br);
        DeleteObject(br);
    }
    // glossy highlight (top half, subtle white)
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 60, 0 };
    (void)bf;
    // shield icon + title
    if (g_shield) {
        HBRUSH br = CreateSolidBrush(RGB(255, 255, 255));
        (void)br;
        DrawIconEx(hdc, 12, (BANNER_H - 40) / 2, g_shield, 40, 40, 0, NULL, DI_NORMAL);
    }
    HFONT of = (HFONT)SelectObject(hdc, g_font_title);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
    TextOutA(hdc, 62, BANNER_H / 2 - 22, "Windows Defender", 16);
    SelectObject(hdc, g_font);
    SetTextColor(hdc, RGB(226, 240, 255));
    TextOutA(hdc, 63, BANNER_H / 2 + 1, "Signature updater for Windows Vista", 35);
    // toolbar strip
    r.top = BANNER_H; r.left = 0; r.right = rc.right; r.bottom = BANNER_H + TOOLBAR_H;
    FillRect(hdc, &r, g_br_toolbar);
    r.top = BANNER_H + TOOLBAR_H; r.bottom = BANNER_H + TOOLBAR_H + 1;
    FillRect(hdc, &r, g_br_border);
}

static BOOL CALLBACK setfont_cb(HWND child, LPARAM lp) {
    SendMessage(child, WM_SETFONT, (WPARAM)(HFONT)lp, TRUE);
    return TRUE;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        RECT rc;
        GetClientRect(hwnd, &rc);
        int y = BANNER_H + TOOLBAR_H;
        // status pane
        CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                      16, y + 10, 620, 18, hwnd, (HMENU)IDC_ST_LINE1, NULL, NULL);
        CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                      16, y + 32, 620, 18, hwnd, (HMENU)IDC_ST_LINE2, NULL, NULL);
        CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                      16, y + 54, 620, 18, hwnd, (HMENU)IDC_ST_LINE3, NULL, NULL);
        CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                      16, y + 76, 620, 18, hwnd, (HMENU)IDC_ST_LINE4, NULL, NULL);
        // buttons
        int by = y + 108;
        CreateWindowA("BUTTON", "Check for updates", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      14, by, 150, 30, hwnd, (HMENU)IDC_UPDATE, NULL, NULL);
        CreateWindowA("BUTTON", "Apply package...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      174, by, 150, 30, hwnd, (HMENU)IDC_APPLY, NULL, NULL);
        CreateWindowA("BUTTON", "Backup", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      334, by, 100, 30, hwnd, (HMENU)IDC_BACKUP, NULL, NULL);
        CreateWindowA("BUTTON", "Rollback", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      444, by, 100, 30, hwnd, (HMENU)IDC_ROLLBACK, NULL, NULL);
        // log
        g_log = CreateWindowA("EDIT", "ready.\r\n",
                              WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                              16, by + 44, 626, 170, hwnd, (HMENU)IDC_LOG, NULL, NULL);
        SendMessage(g_log, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
        refresh_status();
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_UPDATE) start_str(10, NULL);
        else if (id == IDC_APPLY) {
            char file[MAX_PATH] = "";
            OPENFILENAMEA ofn;
            memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = "Signature package (mpam-fe*.exe;mpas-fe*.exe)\0*.exe\0All files\0*.*\0";
            ofn.lpstrFile = file;
            ofn.nMaxFile = sizeof(file);
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameA(&ofn)) start_str(11, file);
        }
        else if (id == IDC_BACKUP) start_simple(2);
        else if (id == IDC_ROLLBACK) start_simple(3);
        break;
    }
    case WM_APP_LOG: {
        char *line = (char *)lp;
        int len = GetWindowTextLength(g_log);
        SendMessage(g_log, EM_SETSEL, len, len);
        char nl[1200];
        snprintf(nl, sizeof(nl), "%s\r\n", line);
        SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)nl);
        free(line);
        return 0;
    }
    case WM_APP_DONE:
        refresh_status();
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        paint_banner(hdc, hwnd);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, RGB(255, 255, 255));
        SetTextColor(hdc, RGB(20, 40, 70));
        return (LRESULT)g_br_white;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int vdu_gui_run(void) {
    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "VDU MainWindow";
    wc.hIcon = LoadIconA(wc.hInstance, MAKEINTRESOURCEA(1));
    RegisterClassA(&wc);

    g_font = CreateFontA(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_font_bold = CreateFontA(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_font_title = CreateFontA(-22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                               OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_br_white = CreateSolidBrush(RGB(255, 255, 255));
    g_br_toolbar = CreateSolidBrush(RGB(240, 244, 249));
    g_br_border = CreateSolidBrush(RGB(190, 200, 212));
    g_shield = LoadIconA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(1));

    HWND hwnd = CreateWindowExA(0, "VDU MainWindow", "Windows Defender",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 680, 520,
                                NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) return 1;
    // apply fonts to all children
    EnumChildWindows(hwnd, setfont_cb, (LPARAM)g_font);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
