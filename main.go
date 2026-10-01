// Package main implements vista-defender-update — an offline updater for
// Windows Defender signature files on legacy Windows (Vista / 7 era).
//
// It downloads the current Microsoft signature package published at
// https://go.microsoft.com/fwlink/?LinkID=121721 (an mpam-fe.exe-style PE
// container holding a CAB archive), extracts mpengine.dll, MpSigStub.exe,
// mpasbase.vdm and mpasdlta.vdm, applies them to the Defender definitions
// directory, patches the Signatures registry values and restarts the
// WinDefend service. A timestamped backup is written first; `rollback`
// restores it.
//
// The code is split into a portable core (this file, plus cab.go / lzx.go /
// mszip.go / pe.go) and a thin Windows-only layer (vista_windows.go) behind
// overridable hooks, which keeps the whole extraction pipeline unit-testable
// on any platform.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	appName    = "Vista Defender Signature Update Tool"
	appVersion = "1.0.0"

	// Microsoft publishes the legacy "Microsoft Antimalware" signature
	// package on this fwlink; it currently redirects to the latest
	// mpam-fe.exe (see docs/ANALYSIS.md).
	downloadURL = "https://go.microsoft.com/fwlink/?LinkID=121721"

	// Signature version written to the registry after applying files.
	// Override with VDU_SIG_VERSION when applying a specific package.
	sigVersionDefault = "1.269.1752.0"

	backupName    = "vdu-backup"
	downloadLimit = 30 * time.Minute
	tsLayout      = "2006-01-02T15-04-05"
)

// regSigPath is the Defender signature registry key (used by the
// Windows-only hook implementations).
const regSigPath = `SOFTWARE\Microsoft\Windows Defender\Signatures`

// Target locations; vars so tests can point them at temporary directories.
var (
	defsDir = `C:\ProgramData\Microsoft\Windows Defender\Definitions`
	sysDir  = `C:\Windows\System32`
)

// sigNames are the Defender files that get applied. The package also
// carries mpavbase.vdm / mpavdlta.vdm (antivirus definitions used by MSE);
// Vista Defender is antispyware-only, so those are extracted but not applied.
var sigNames = []string{"mpengine.dll", "MpSigStub.exe", "mpasbase.vdm", "mpasdlta.vdm"}

type backupEntry struct {
	OriginalPath string
	BackupPath   string
	Exists       bool
	Size         int64
}

type backupManifest struct {
	Timestamp   string        `json:"timestamp"`
	BackupDir   string        `json:"backupDir"`
	Files       []backupEntry `json:"files"`
	RegistryVer string        `json:"registryVersion"`
}

var errWindowsOnly = errors.New("requires a native Windows build")

// Windows-specific facilities are called through these hooks. The defaults
// are no-ops that keep the portable build honest; vista_windows.go installs
// real implementations via init(); tests replace them with fakes.
var (
	hookRegistryReadVersion  = func() (string, bool) { return "", false }
	hookRegistryWriteVersion = func(string) error { return errWindowsOnly }
	hookServiceInstalled     = func() bool { return false }
	hookRunService           = func(string) error { return errWindowsOnly }
)

func sigVersion() string {
	if v := os.Getenv("VDU_SIG_VERSION"); v != "" {
		return v
	}
	return sigVersionDefault
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	var err error
	switch strings.ToLower(os.Args[1]) {
	case "status":
		cmdStatus()
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "rollback":
		err = cmdRollback()
	case "backup":
		err = cmdBackup()
	case "download":
		err = cmdDownload(os.Args[2:])
	case "apply":
		err = cmdApply(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
	must(err)
}

func usage() {
	fmt.Printf("%s v%s\n\n", appName, appVersion)
	fmt.Println("Commands:")
	fmt.Println("  status              Show current Defender status")
	fmt.Println("  update [flags]      Download & apply latest signatures")
	fmt.Println("  download [-out f]   Download Vista signature package")
	fmt.Println("  apply -local <dir>  Apply pre-extracted signatures")
	fmt.Println("  backup              Back up current signatures")
	fmt.Println("  rollback            Restore original signatures")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -dry-run            Preview without making changes")
	fmt.Println("  -local <dir>        Use local directory of signature files")
	fmt.Println("  -out <file>         Output file for download")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  VDU_SIG_VERSION     Registry version written by apply (default " + sigVersionDefault + ")")
}

func cmdStatus() {
	fmt.Printf("=== %s v%s ===\n\n", appName, appVersion)
	fmt.Printf("Definitions dir: %s\n", defsDir)
	for _, f := range sigNames {
		p := filepath.Join(defsDir, f)
		if info, err := os.Stat(p); err == nil {
			fmt.Printf("  %-20s %10.1f KB\n", f, float64(info.Size())/1024)
		} else {
			fmt.Printf("  %-20s  (missing)\n", f)
		}
	}
	if v, ok := hookRegistryReadVersion(); ok {
		fmt.Printf("Registry Antivirus: %s\n", v)
	} else {
		fmt.Println("Registry: n/a")
	}
	if hookServiceInstalled() {
		fmt.Println("WinDefend service: installed")
	} else {
		fmt.Println("WinDefend service: not found")
	}
	fmt.Printf("Apply would set version: %s\n", sigVersion())
	if mn, err := loadManifest(); err == nil {
		fmt.Printf("Last backup: %s (%s, %d files)\n", mn.BackupDir, mn.Timestamp, len(mn.Files))
	}
}

func cmdUpdate(args []string) error {
	dryRun, localDir := parseFlags(args)
	return orchestrate(dryRun, localDir)
}

func cmdApply(args []string) error {
	localDir, dryRun := "", false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-local":
			if i+1 < len(args) {
				localDir = args[i+1]
				i++
			}
		case "-dry-run":
			dryRun = true
		}
	}
	if localDir == "" {
		return errors.New("usage: apply -local <dir>")
	}
	return orchestrate(dryRun, localDir)
}

// orchestrate runs the shared update/apply pipeline: environment check,
// service stop, backup, signature acquisition, apply, registry patch and
// service restart. When -dry-run is set nothing on the system is modified
// (the download still happens, as it is read-only).
func orchestrate(dryRun bool, localDir string) error {
	if dryRun {
		fmt.Println("[DRY RUN]")
	}
	fmt.Println("[1/6] Checking environment...")
	if err := checkEnv(); err != nil {
		return err
	}
	stopped := false
	if !dryRun && hookServiceInstalled() {
		fmt.Println("      Stopping WinDefend (frees signature files)...")
		if err := hookRunService("stop"); err != nil {
			fmt.Printf("      Warning: stop failed (%v); continuing\n", err)
		} else {
			stopped = true
		}
	}
	err := runPipeline(dryRun, localDir)
	if stopped {
		fmt.Println("[6/6] Starting WinDefend...")
		if serr := hookRunService("start"); serr != nil {
			fmt.Printf("      Warning: start failed (%v)\n", serr)
			if err == nil {
				err = fmt.Errorf("start WinDefend: %w", serr)
			}
		}
	} else if !dryRun {
		fmt.Println("[6/6] Restarting WinDefend... (service not running; skipped)")
	}
	return err
}

func runPipeline(dryRun bool, localDir string) error {
	fmt.Println("[2/6] Backing up...")
	mn, err := doBackup(dryRun)
	if err != nil {
		return err
	}
	fmt.Println("[3/6] Getting signatures...")
	var sigDir string
	if localDir != "" {
		sigDir = localDir
		fmt.Printf("  Using local: %s\n", localDir)
	} else {
		p, err := doDownload()
		if err != nil {
			return err
		}
		if dryRun {
			fmt.Printf("  [DRY RUN] Would extract %s\n", p)
		} else {
			sigDir, err = doExtract(p)
			if err != nil {
				return err
			}
		}
	}
	fmt.Println("[4/6] Applying...")
	if sigDir != "" {
		if err := doApply(sigDir, mn, dryRun); err != nil {
			return err
		}
	}
	fmt.Println("[5/6] Patching registry...")
	if err := doRegistry(dryRun); err != nil {
		return err
	}
	fmt.Println("\nDone.")
	return nil
}

func cmdBackup() error {
	mn, err := doBackup(false)
	if err != nil {
		return err
	}
	fmt.Printf("Backup: %s\n", mn.BackupDir)
	return nil
}

func cmdRollback() error {
	mn, err := loadManifest()
	if err != nil {
		return err
	}
	stopped := false
	if hookServiceInstalled() {
		if err := hookRunService("stop"); err != nil {
			fmt.Printf("  Warning: stop failed (%v); continuing\n", err)
		} else {
			stopped = true
		}
	}
	doRollback(mn)
	if stopped {
		if err := hookRunService("start"); err != nil {
			fmt.Printf("  Warning: start failed (%v)\n", err)
		}
	}
	fmt.Println("Rolled back.")
	return nil
}

func cmdDownload(args []string) error {
	out := "mpam-fe.exe"
	for i := 0; i < len(args); i++ {
		if args[i] == "-out" && i+1 < len(args) {
			out = args[i+1]
			i++
		}
	}
	p, err := downloadToFile(downloadURL, out)
	if err != nil {
		return err
	}
	fmt.Printf("Downloaded: %s\n", p)
	return nil
}

func parseFlags(args []string) (dryRun bool, localDir string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-dry-run":
			dryRun = true
		case "-local":
			if i+1 < len(args) {
				localDir = args[i+1]
				i++
			}
		}
	}
	return
}

func checkEnv() error {
	if _, err := os.Stat(defsDir); err != nil {
		return fmt.Errorf("definitions dir not found: %s", defsDir)
	}
	if _, err := os.Stat(filepath.Join(sysDir, "msMpEng.exe")); err != nil {
		if _, err2 := os.Stat(filepath.Join(sysDir, "mpengine.dll")); err2 != nil {
			return errors.New("Vista Defender not detected")
		}
	}
	return nil
}

func backupRoot() string {
	return filepath.Join(filepath.Dir(defsDir), backupName)
}

func manifestPath() string {
	return filepath.Join(backupRoot(), "manifest.json")
}

func doBackup(dryRun bool) (*backupManifest, error) {
	ver, _ := hookRegistryReadVersion()
	mn := &backupManifest{
		Timestamp:   time.Now().Format(tsLayout),
		BackupDir:   filepath.Join(backupRoot(), time.Now().Format(tsLayout)),
		RegistryVer: ver,
	}
	if dryRun {
		fmt.Println("  [DRY RUN] Would back up signature files")
		return mn, nil
	}
	if err := os.MkdirAll(mn.BackupDir, 0o755); err != nil {
		return nil, err
	}
	for _, f := range sigNames {
		orig := filepath.Join(defsDir, f)
		_, err := os.Stat(orig)
		if err != nil {
			mn.Files = append(mn.Files, backupEntry{OriginalPath: orig, Exists: false})
			continue
		}
		bp := filepath.Join(mn.BackupDir, f)
		if err := copyFile(orig, bp); err != nil {
			return nil, fmt.Errorf("backup %s: %w", f, err)
		}
		info, _ := os.Stat(orig)
		mn.Files = append(mn.Files, backupEntry{OriginalPath: orig, BackupPath: bp, Exists: true, Size: info.Size()})
		fmt.Printf("  Backed up: %s (%.1f KB)\n", f, float64(info.Size())/1024)
	}
	if err := saveManifest(mn); err != nil {
		return nil, err
	}
	return mn, nil
}

func doApply(sigDir string, mn *backupManifest, dryRun bool) error {
	_ = mn
	if dryRun {
		for _, f := range sigNames {
			src := filepath.Join(sigDir, f)
			if _, err := os.Stat(src); err == nil {
				fmt.Printf("  Would apply: %s\n", f)
			} else {
				fmt.Printf("  [MISSING] %s\n", f)
			}
		}
		return nil
	}
	n := 0
	for _, f := range sigNames {
		src := filepath.Join(sigDir, f)
		dst := filepath.Join(defsDir, f)
		if _, err := os.Stat(src); err != nil {
			fmt.Printf("  [SKIP] %s\n", f)
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("apply %s: %w", f, err)
		}
		fmt.Printf("  Applied: %s\n", f)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no signature files found in %s", sigDir)
	}
	return nil
}

func doRegistry(dryRun bool) error {
	if dryRun {
		fmt.Printf("  [DRY RUN] Would set registry version %s\n", sigVersion())
		return nil
	}
	if err := hookRegistryWriteVersion(sigVersion()); err != nil {
		return fmt.Errorf("registry write: %w", err)
	}
	fmt.Printf("  Version set to %s\n", sigVersion())
	return nil
}

func doRollback(mn *backupManifest) {
	for _, e := range mn.Files {
		if !e.Exists {
			// The file did not exist before apply; undo a created file.
			if err := os.Remove(e.OriginalPath); err == nil {
				fmt.Printf("  Removed: %s\n", filepath.Base(e.OriginalPath))
			}
			continue
		}
		if err := copyFile(e.BackupPath, e.OriginalPath); err != nil {
			fmt.Printf("  Rollback %s: %v\n", filepath.Base(e.OriginalPath), err)
		} else {
			fmt.Printf("  Restored: %s\n", filepath.Base(e.OriginalPath))
		}
	}
	if mn.RegistryVer != "" {
		if err := hookRegistryWriteVersion(mn.RegistryVer); err == nil {
			fmt.Printf("  Registry restored to %s\n", mn.RegistryVer)
		}
	}
}

func doDownload() (string, error) {
	out := filepath.Join(os.TempDir(), "mpam-fe.exe")
	return downloadToFile(downloadURL, out)
}

func downloadToFile(url, out string) (string, error) {
	client := &http.Client{Timeout: downloadLimit}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := out + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	w, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(tmp)
		return "", copyErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return "", closeErr
	}
	if resp.ContentLength > 0 && w != resp.ContentLength {
		os.Remove(tmp)
		return "", fmt.Errorf("incomplete download: got %d of %d bytes", w, resp.ContentLength)
	}
	if err := os.Rename(tmp, out); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if w < 10*1024*1024 {
		fmt.Printf("Warning: only %.1f MB downloaded\n", float64(w)/(1024*1024))
	}
	return out, nil
}

func doExtract(pkg string) (string, error) {
	out := filepath.Join(os.TempDir(), "vista-sigs")
	if err := os.RemoveAll(out); err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", err
	}
	if err := extractPackage(pkg, out); err != nil {
		return "", fmt.Errorf("extraction: %w (use apply -local with pre-extracted files)", err)
	}
	for _, f := range []string{"mpasbase.vdm", "mpasdlta.vdm"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			return "", fmt.Errorf("%s missing after extraction", f)
		}
	}
	return out, nil
}

func saveManifest(m *backupManifest) error {
	d, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	d = append(d, '\n')
	return os.WriteFile(manifestPath(), d, 0o644)
}

func loadManifest() (*backupManifest, error) {
	d, err := os.ReadFile(manifestPath())
	if err != nil {
		return nil, fmt.Errorf("no backup: %w", err)
	}
	var m backupManifest
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	os.Exit(1)
}
