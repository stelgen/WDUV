package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempPaths(t *testing.T) (defs, sys string) {
	t.Helper()
	oldDefs, oldSys := defsDir, sysDir
	oldEnv := os.Getenv("VDU_SIG_VERSION")
	os.Unsetenv("VDU_SIG_VERSION")
	t.Cleanup(func() {
		defsDir, sysDir = oldDefs, oldSys
		os.Setenv("VDU_SIG_VERSION", oldEnv)
	})
	defs = filepath.Join(t.TempDir(), "ProgramData", "Microsoft", "Windows Defender", "Definitions")
	sys = filepath.Join(t.TempDir(), "Windows", "System32")
	defsDir, sysDir = defs, sys
	if err := os.MkdirAll(defsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return defs, sys
}

type fakeHooks struct {
	regVal   string
	regWrite int
	svcOps   []string
	ver      string
}

func installFakeHooks(t *testing.T, fh *fakeHooks) {
	t.Helper()
	old := hookRegistryReadVersion
	oldW := hookRegistryWriteVersion
	oldI := hookServiceInstalled
	oldR := hookRunService
	t.Cleanup(func() {
		hookRegistryReadVersion, hookRegistryWriteVersion = old, oldW
		hookServiceInstalled, hookRunService = oldI, oldR
	})
	hookRegistryReadVersion = func() (string, bool) { return fh.ver, fh.ver != "" }
	hookRegistryWriteVersion = func(v string) error { fh.regVal = v; fh.regWrite++; return nil }
	hookServiceInstalled = func() bool { return true }
	hookRunService = func(verb string) error { fh.svcOps = append(fh.svcOps, verb); return nil }
}

func TestParseFlags(t *testing.T) {
	dry, local := parseFlags([]string{"-dry-run", "-local", "/tmp/sigs"})
	if !dry || local != "/tmp/sigs" {
		t.Fatalf("got dry=%v local=%q", dry, local)
	}
	dry, local = parseFlags([]string{"-local"})
	if dry || local != "" {
		t.Fatalf("dangling -local: dry=%v local=%q", dry, local)
	}
}

func TestCheckEnv(t *testing.T) {
	defs, sys := withTempPaths(t)
	if err := checkEnv(); err == nil || !strings.Contains(err.Error(), "definitions dir not found") {
		// defs dir exists here; make sure it reports missing engine instead
		_ = defs
	}
	if err := os.WriteFile(filepath.Join(defs, "mpasbase.vdm"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkEnv(); err == nil || !strings.Contains(err.Error(), "Vista Defender not detected") {
		t.Fatalf("expected Defender-not-detected, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(sys, "msMpEng.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkEnv(); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestBackupApplyRollback(t *testing.T) {
	defs, sys := withTempPaths(t)
	fh := &fakeHooks{ver: "1.0.0.0"}
	installFakeHooks(t, fh)
	if err := os.WriteFile(filepath.Join(sys, "mpengine.dll"), []byte("engine"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := map[string]string{"mpengine.dll": "old engine", "mpasbase.vdm": "old base"}
	for name, body := range old {
		if err := os.WriteFile(filepath.Join(defs, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	local := filepath.Join(t.TempDir(), "local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	newFiles := map[string]string{
		"mpengine.dll":  "new engine",
		"MpSigStub.exe": "new stub",
		"mpasbase.vdm":  "new base",
		"mpasdlta.vdm":  "new dlta",
	}
	for name, body := range newFiles {
		if err := os.WriteFile(filepath.Join(local, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdApply([]string{"-local", local}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for name, want := range newFiles {
		got, err := os.ReadFile(filepath.Join(defs, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s: got %q want %q", name, got, want)
		}
	}
	if fh.regVal != sigVersionDefault || fh.regWrite != 1 {
		t.Fatalf("registry: val=%q writes=%d", fh.regVal, fh.regWrite)
	}
	if len(fh.svcOps) != 2 || fh.svcOps[0] != "stop" || fh.svcOps[1] != "start" {
		t.Fatalf("service ops: %v", fh.svcOps)
	}
	mn, err := loadManifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(mn.Files) != len(sigNames) {
		t.Fatalf("manifest files: %d", len(mn.Files))
	}
	if mn.RegistryVer != "1.0.0.0" {
		t.Fatalf("manifest regver: %q", mn.RegistryVer)
	}

	// Rollback restores old files and deletes files that did not exist.
	if err := cmdRollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	for name, want := range old {
		got, err := os.ReadFile(filepath.Join(defs, name))
		if err != nil {
			t.Fatalf("%s after rollback: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s after rollback: got %q want %q", name, got, want)
		}
	}
	for _, name := range []string{"MpSigStub.exe", "mpasdlta.vdm"} {
		if _, err := os.Stat(filepath.Join(defs, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been removed by rollback", name)
		}
	}
	if fh.regVal != "1.0.0.0" {
		t.Fatalf("registry not restored: %q", fh.regVal)
	}
}

func TestBackupDryRun(t *testing.T) {
	defs, _ := withTempPaths(t)
	if err := os.WriteFile(filepath.Join(defs, "mpengine.dll"), []byte("engine"), 0o644); err != nil {
		t.Fatal(err)
	}
	mn, err := doBackup(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mn.BackupDir); !os.IsNotExist(err) {
		t.Fatal("dry-run backup must not create directories")
	}
	if _, err := os.Stat(manifestPath()); !os.IsNotExist(err) {
		t.Fatal("dry-run backup must not write manifest")
	}
}

func TestApplyDryRun(t *testing.T) {
	defs, sys := withTempPaths(t)
	_ = defs
	fh := &fakeHooks{ver: "1.0.0.0"}
	installFakeHooks(t, fh)
	if err := os.WriteFile(filepath.Join(sys, "mpengine.dll"), []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(defs, "mpengine.dll"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "mpengine.dll"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdApply([]string{"-local", local, "-dry-run"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(defs, "mpengine.dll"))
	if string(got) != "old" {
		t.Fatal("dry-run apply modified the definitions dir")
	}
	if fh.regWrite != 0 || len(fh.svcOps) != 0 {
		t.Fatal("dry-run must not touch registry/service")
	}
}

func TestDownloadToFile(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("hello package"))
		case "/short":
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("too short"))
		case "/err":
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p, err := downloadToFile(srv.URL+"/ok", filepath.Join(dir, "a.exe"))
	if err != nil {
		t.Fatalf("ok: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "hello package" {
		t.Fatalf("ok: content %q", b)
	}
	if _, err := os.Stat(p + ".part"); !os.IsNotExist(err) {
		t.Fatal(".part file must be renamed away")
	}
	if _, err := downloadToFile(srv.URL+"/short", filepath.Join(dir, "b.exe")); err == nil {
		t.Fatal("short download must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "b.exe")); !os.IsNotExist(err) {
		t.Fatal("failed download must not leave the target file")
	}
	if _, err := os.Stat(filepath.Join(dir, "b.exe.part")); !os.IsNotExist(err) {
		t.Fatal("failed download must clean up .part")
	}
	if _, err := downloadToFile(srv.URL+"/err", filepath.Join(dir, "c.exe")); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("500: got %v", err)
	}
}

func TestOrchestrateDryRunDoesNotStopService(t *testing.T) {
	defs, sys := withTempPaths(t)
	fh := &fakeHooks{ver: "1.0.0.0"}
	installFakeHooks(t, fh)
	if err := os.WriteFile(filepath.Join(sys, "mpengine.dll"), []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = defs
	local := filepath.Join(t.TempDir(), "local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := orchestrate(true, local); err != nil {
		t.Fatalf("orchestrate dry: %v", err)
	}
	if len(fh.svcOps) != 0 {
		t.Fatalf("dry-run must not stop/start service: %v", fh.svcOps)
	}
}

func TestApplyRequiresLocal(t *testing.T) {
	if err := cmdApply(nil); err == nil || !strings.Contains(err.Error(), "usage: apply -local") {
		t.Fatalf("got %v", err)
	}
}

func TestSigVersionEnv(t *testing.T) {
	t.Setenv("VDU_SIG_VERSION", "9.9.9.9")
	if got := sigVersion(); got != "9.9.9.9" {
		t.Fatalf("sigVersion: %q", got)
	}
}
