//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// On Windows the hooks talk to the real Defender registry keys and the
// WinDefend service. Everything runs through the same hook vars the
// portable build and the tests use, so behaviour is identical.

func init() {
	hookRegistryReadVersion = func() (string, bool) {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.QUERY_VALUE)
		if err != nil {
			return "", false
		}
		defer k.Close()
		s, _, err := k.GetStringValue("Antivirus")
		if err != nil {
			return "", false
		}
		return s, true
	}
	hookRegistryWriteVersion = func(v string) error {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, regSigPath, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		defer k.Close()
		if err := k.SetStringValue("Antivirus", v); err != nil {
			return err
		}
		return k.SetStringValue("AntiSpyware", v)
	}
	hookServiceInstalled = func() bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\WinDefend`, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		k.Close()
		return true
	}
	hookRunService = func(verb string) error {
		verb = strings.ToLower(verb)
		if verb != "stop" && verb != "start" {
			return fmt.Errorf("unknown service verb %q", verb)
		}
		cmd := exec.Command("cmd.exe", "/C", "net "+verb+" WinDefend")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
}
