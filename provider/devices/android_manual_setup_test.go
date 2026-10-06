package devices

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GADS/common/models"
	"GADS/provider/config"
)

// A command recorder verifies the important absence of installation, removal,
// and TCP-mode commands. No real handset is accessed by these tests.
func manualSetupFixture(t *testing.T, installed bool) (*AndroidDevice, string) {
	t.Helper()
	previousManual, previousUSB := config.AndroidManualAPKInstall, config.AndroidUSBOnly
	config.AndroidManualAPKInstall, config.AndroidUSBOnly = true, true
	t.Cleanup(func() { config.AndroidManualAPKInstall, config.AndroidUSBOnly = previousManual, previousUSB })
	dir := t.TempDir()
	log := filepath.Join(dir, "commands.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GADS_TEST_ADB_LOG\"\n"
	script += "if [ \"$3 $4 $5 $6 $7\" != 'shell pm path com.gads.settings ' ]; then exit 99; fi\n"
	if installed {
		script += "printf 'package:/data/app/com.gads.settings/base.apk\\n'\n"
	} else {
		script += "exit 1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "adb"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GADS_TEST_ADB_LOG", log)
	d := &AndroidDevice{RuntimeState: RuntimeState{Context: context.Background(), DBDevice: models.DBDevice{UDID: "test-device"}}, ADBPort: "43210"}
	return d, log
}

func TestManualAndroidSetupKeepsInstalledHelperAndUSBConnection(t *testing.T) {
	d, log := manualSetupFixture(t, true)
	for _, action := range []func() error{d.cleanupOldApps, d.installGadsSettingsApp, d.enableADBTCPMode, d.forwardADB} {
		if err := action(); err != nil {
			t.Fatal(err)
		}
	}
	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(commands)) != "-s test-device shell pm path com.gads.settings" {
		t.Fatalf("unexpected device mutations: %s", commands)
	}
	if d.ADBPort != "" {
		t.Fatal("USB-only mode still advertises an ADB tunnel")
	}
}

func TestMissingManualHelperDoesNotFallBackToADBInstallation(t *testing.T) {
	d, log := manualSetupFixture(t, false)
	err := d.installGadsSettingsApp()
	if err == nil || !strings.Contains(err.Error(), "installed manually") {
		t.Fatalf("expected actionable manual installation error, got %v", err)
	}
	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), " install ") || strings.Contains(string(commands), "uninstall") {
		t.Fatal("missing helper triggered an ADB installation")
	}
}
