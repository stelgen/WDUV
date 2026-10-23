package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	appName     = "Vista Defender Signature Update Tool"
	appVersion  = "1.0.0"
	regSigPath  = `SOFTWARE\Microsoft\Windows Defender\Signatures`
	defsDir     = `C:\ProgramData\Microsoft\Windows Defender\Definitions`
	backupName  = "vdu-backup"
	downloadURL = "https://go.microsoft.com/fwlink/?LinkID=121721"
)

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

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch strings.ToLower(os.Args[1]) {
	case "status":
		cmdStatus()
	case "update":
		cmdUpdate(os.Args[2:])
	case "rollback":
		cmdRollback()
	case "backup":
		cmdBackup()
	case "download":
		cmdDownload(os.Args[2:])
	case "apply":
		cmdApply(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
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
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		for _, v := range []string{"Antivirus", "AntiSpyware"} {
			if s, _, err := k.GetStringValue(v); err == nil {
				fmt.Printf("Registry %s = %s\n", v, s)
			}
		}
	} else {
		fmt.Println("Registry: not found")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\WinDefend`, registry.QUERY_VALUE); err == nil {
		k.Close()
		fmt.Println("WinDefend service: installed")
	} else {
		fmt.Println("WinDefend service: not found")
	}
}

func cmdUpdate(args []string) {
	dryRun, localDir := parseFlags(args)
	if dryRun {
		fmt.Println("[DRY RUN]")
	}
	fmt.Println("[1/6] Checking environment...")
	must(checkEnv())
	fmt.Println("[2/6] Backing up...")
	mn, err := doBackup()
	must(err)
	fmt.Println("[3/6] Getting signatures...")
	var sigDir string
	if localDir != "" {
		sigDir = localDir
		fmt.Printf("  Using local: %s\n", localDir)
	} else {
		p, err := doDownload()
		must(err)
		if dryRun {
			fmt.Printf("  [DRY RUN] Would extract %s\n", p)
			sigDir = "<dry>"
		} else {
			sigDir, err = doExtract(p)
			must(err)
		}
	}
	fmt.Println("[4/6] Applying...")
	must(doApply(sigDir, mn, dryRun))
	fmt.Println("[5/6] Patching registry...")
	must(doRegistry(dryRun))
	fmt.Println("[6/6] Restarting WinDefend...")
	must(restartService(dryRun))
	fmt.Println("\nDone.")
}

func cmdDownload(args []string) {
	out := "mpas-fe.exe"
	for i := 0; i < len(args); i++ {
		if args[i] == "-out" && i+1 < len(args) {
			out = args[i+1]
		}
	}
	p, err := downloadToFile(downloadURL, out)
	must(err)
	fmt.Printf("Downloaded: %s\n", p)
}

func cmdApply(args []string) {
	localDir, dryRun := "", false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-local":
			if i+1 < len(args) {
				localDir = args[i+1]
			}
		case "-dry-run":
			dryRun = true
		}
	}
	if localDir == "" {
		fatal(fmt.Errorf("Usage: apply -local <dir>"))
	}
	must(checkEnv())
	mn, err := doBackup()
	must(err)
	must(doApply(localDir, mn, dryRun))
	must(doRegistry(dryRun))
	must(restartService(dryRun))
	fmt.Println("\nApplied.")
}

func cmdBackup() {
	mn, err := doBackup()
	must(err)
	fmt.Printf("Backup: %s\n", mn.BackupDir)
}

func cmdRollback() {
	mn, err := loadManifest()
	must(err)
	doRollback(mn)
	fmt.Println("Rolled back.")
}

func parseFlags(args []string) (dryRun bool, localDir string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-dry-run":
			dryRun = true
		case "-local":
			if i+1 < len(args) {
				localDir = args[i+1]
			}
		}
	}
	return
}

func checkEnv() error {
	if _, err := os.Stat(defsDir); err != nil {
		return fmt.Errorf("definitions dir not found: %s", defsDir)
	}
	if _, err := os.Stat(`C:\Windows\System32\msMpEng.exe`); err != nil {
		if _, err2 := os.Stat(`C:\Windows\System32\mpengine.dll`); err2 != nil {
			return fmt.Errorf("Vista Defender not detected")
		}
	}
	return nil
}

func doBackup() (*backupManifest, error) {
	ts := time.Now().Format("2006-01-02T15-04-05")
	sd := os.Getenv("SystemDrive")
	if sd == "" {
		sd = "C:"
	}
	bkDir := filepath.Join(sd, "ProgramData", "Microsoft", "Windows Defender", backupName, ts)
	if err := os.MkdirAll(bkDir, 0755); err != nil {
		return nil, err
	}
	ver := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.QUERY_VALUE); err == nil {
		if s, _, err := k.GetStringValue("Antivirus"); err == nil {
			ver = s
		}
		k.Close()
	}
	var files []backupEntry
	for _, f := range sigNames {
		orig := filepath.Join(defsDir, f)
		_, err := os.Stat(orig)
		if err != nil {
			files = append(files, backupEntry{OriginalPath: orig, Exists: false})
			continue
		}
		bp := filepath.Join(bkDir, f)
		if err := copyFile(orig, bp); err != nil {
			return nil, fmt.Errorf("backup %s: %v", f, err)
		}
		info, _ := os.Stat(orig)
		files = append(files, backupEntry{OriginalPath: orig, BackupPath: bp, Exists: true, Size: info.Size()})
		fmt.Printf("  Backed up: %s (%.1f KB)\n", f, float64(info.Size())/1024)
	}
	mn := &backupManifest{Timestamp: ts, BackupDir: bkDir, Files: files, RegistryVer: ver}
	if err := saveManifest(mn); err != nil {
		return nil, err
	}
	return mn, nil
}

func doApply(sigDir string, mn *backupManifest, dryRun bool) error {
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
			return fmt.Errorf("apply %s: %v", f, err)
		}
		fmt.Printf("  Applied: %s\n", f)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no files in %s", sigDir)
	}
	return nil
}

func doRegistry(dryRun bool) error {
	if dryRun {
		fmt.Println("  [DRY RUN] Would patch registry")
		return nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("registry write: %v", err)
	}
	defer k.Close()
	k.SetStringValue("Antivirus", "1.269.1752.0")
	k.SetStringValue("AntiSpyware", "1.269.1752.0")
	k.Close()
	fmt.Println("  Version set to 1.269.1752.0")
	return nil
}

func restartService(dryRun bool) error {
	if dryRun {
		fmt.Println("  [DRY RUN] Would restart WinDefend")
		return nil
	}
	return runCmd("cmd.exe", "/C", "net stop WinDefend && net start WinDefend")
}

func doDownload() (string, error) {
	out := filepath.Join(os.TempDir(), "mpas-fe.exe")
	return downloadToFile(downloadURL, out)
}

func downloadToFile(url, out string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()
	w, err := io.Copy(f, resp.Body)
	if err != nil {
		return "", err
	}
	if w < 10*1024*1024 {
		fmt.Printf("Warning: only %.1f MB downloaded\n", float64(w)/(1024*1024))
	}
	return out, nil
}

func doExtract(pkg string) (string, error) {
	out := filepath.Join(os.TempDir(), "vista-sigs")
	if err := os.MkdirAll(out, 0755); err != nil {
		return "", err
	}
	data, err := os.ReadFile(pkg)
	if err != nil {
		return "", err
	}
	ex, err := extractPE(data, out)
	if err != nil {
		return "", fmt.Errorf("extraction: %v (use -local with pre-extracted files)", err)
	}
	for _, f := range []string{"mpasbase.vdm", "mpasdlta.vdm"} {
		if !ex[f] {
			return "", fmt.Errorf("%s missing after extraction", f)
		}
	}
	return out, nil
}

func extractPE(data []byte, out string) (map[string]bool, error) {
	res := make(map[string]bool)
	for _, p := range findAll(data, []byte{0x4D, 0x5A}) {
		if p+0x40 > len(data) {
			continue
		}
		peOff := int(int32(data[p+0x3C]) | int32(data[p+0x3D])<<8 |
			int32(data[p+0x3E])<<16 | int32(data[p+0x3F])<<24)
		if peOff <= 0 || p+peOff+24 > len(data) {
			continue
		}
		if !bytes.Equal(data[p+peOff:p+peOff+4], []byte("PE\x00\x00")) {
			continue
		}
		end := peEnd(data, p, peOff)
		name := "mpengine.dll"
		if end-p < 5*1024*1024 {
			name = "MpSigStub.exe"
		}
		f := filepath.Join(out, name)
		if err := os.WriteFile(f, data[p:end], 0644); err == nil {
			res[name] = true
			fmt.Printf("  Extracted: %s (%.1f KB)\n", name, float64(end-p)/1024)
		}
	}
	for i, p := range findAll(data, []byte{0x56, 0x44, 0x4D, 0x00}) {
		if i >= 2 {
			break
		}
		end := blobEnd(data, p)
		if end-p > 1024*1024 {
			name := "mpasbase.vdm"
			if i > 0 {
				name = "mpasdlta.vdm"
			}
			f := filepath.Join(out, name)
			if err := os.WriteFile(f, data[p:end], 0644); err == nil {
				res[name] = true
				fmt.Printf("  Extracted: %s (%.1f KB)\n", name, float64(end-p)/1024)
			}
		}
	}
	if len(res) == 0 {
		return res, fmt.Errorf("no signature files found in PE data")
	}
	return res, nil
}

func findAll(data, pat []byte) []int {
	var r []int
	for i := 0; i+len(pat) <= len(data); i++ {
		match := true
		for j := range pat {
			if data[i+j] != pat[j] {
				match = false
				break
			}
		}
		if match {
			r = append(r, i)
			i += len(pat)
		}
	}
	return r
}

func peEnd(data []byte, start, peOff int) int {
	if peOff+24 > len(data) {
		return start + 0x100
	}
	numSecs := int(uint16(data[peOff+6]) | uint16(data[peOff+7])<<8)
	tabEnd := peOff + 24 + numSecs*40
	if tabEnd > len(data) {
		return len(data)
	}
	maxEnd := tabEnd
	for i := 0; i < numSecs; i++ {
		so := peOff + 24 + i*40
		if so+40 > len(data) {
			break
		}
		vSize := int(int32(data[so+8]) | int32(data[so+9])<<8 |
			int32(data[so+10])<<16 | int32(data[so+11])<<24)
		vAddr := int(int32(data[so+12]) | int32(data[so+13])<<8 |
			int32(data[so+14])<<16 | int32(data[so+15])<<24)
		if vAddr+vSize > maxEnd {
			maxEnd = vAddr + vSize
		}
	}
	return start + maxEnd
}

func blobEnd(data []byte, start int) int {
	for i := start + 10; i+2 <= len(data); i++ {
		if data[i] == 0x4D && data[i+1] == 0x5A && i+0x40 < len(data) {
			peOff := int(data[i+0x3C])
			if peOff > 0 && i+peOff+4 <= len(data) &&
				data[i+peOff] == 'P' && data[i+peOff+1] == 'E' {
				return i
			}
		}
	}
	return len(data)
}

func doRollback(mn *backupManifest) {
	for _, e := range mn.Files {
		if !e.Exists {
			continue
		}
		if err := copyFile(e.BackupPath, e.OriginalPath); err != nil {
			fmt.Printf("  Rollback %s: %v\n", filepath.Base(e.OriginalPath), err)
		} else {
			fmt.Printf("  Restored: %s\n", filepath.Base(e.OriginalPath))
		}
	}
	if mn.RegistryVer != "" {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.SET_VALUE); err == nil {
			k.SetStringValue("Antivirus", mn.RegistryVer)
			k.SetStringValue("AntiSpyware", mn.RegistryVer)
			k.Close()
			fmt.Printf("  Registry restored to %s\n", mn.RegistryVer)
		}
	}
}

func saveManifest(m *backupManifest) error {
	d, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	d = append(d, '\n')
	return os.WriteFile(manifestPath(), d, 0644)
}

func loadManifest() (*backupManifest, error) {
	d, err := os.ReadFile(manifestPath())
	if err != nil {
		return nil, fmt.Errorf("no backup: %v", err)
	}
	var m backupManifest
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func manifestPath() string {
	return filepath.Join(defsDir, backupName, "manifest.json")
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
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func runCmd(name string, args ...string) error {
	return nil
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
