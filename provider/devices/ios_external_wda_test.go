package devices

import (
	"GADS/common/models"
	"testing"

	"github.com/Masterminds/semver"
)

func TestExternalWDARequiresExplicitExactUDID(t *testing.T) {
	for _, tc := range []struct {
		name, udid, configured string
		want                   bool
	}{
		{"unset", "fixture-se3", "", false},
		{"blank", "fixture-se3", " , , \n", false},
		{"empty device", "", ", ,", false},
		{"exact", "fixture-se3", "fixture-se3", true},
		{"list", "fixture-se3", "other, fixture-se3 ,another", true},
		{"trim configured entry", "fixture-se3", "\n fixture-se3\t", true},
		{"different device", "fixture-se3", "other", false},
		{"prefix is not enough", "fixture-se3", "fixture-se", false},
		{"suffix is not enough", "fixture-se3", "se3", false},
		{"longer device", "fixture-se3-extra", "fixture-se3", false},
		{"case sensitive", "fixture-se3", "FIXTURE-SE3", false},
		{"wildcard is not global", "fixture-se3", "*", false},
		{"glob is not supported", "fixture-se3", "fixture-*", false},
		{"substring in another entry", "fixture-se3", "prefix-fixture-se3,other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := usesExternalWDA(tc.udid, tc.configured); got != tc.want {
				t.Errorf("usesExternalWDA(%q, %q) = %v, want %v", tc.udid, tc.configured, got, tc.want)
			}
		})
	}
}

func TestExternalWDAAttachDoesNotDeclareDeviceReady(t *testing.T) {
	t.Setenv("GADS_IOS_EXTERNAL_WDA_UDIDS", "fixture-se3")
	device := &IOSDevice{
		RuntimeState: RuntimeState{
			DBDevice:      models.DBDevice{UDID: "fixture-se3"},
			SemVer:        semver.MustParse("18.0.0"),
			ProviderState: "preparing",
		},
		WdaReadyChan: make(chan bool, 1),
	}
	// No device entry, app archive, network service or runner is provided. The
	// explicit attach path must not try to install or launch WDA itself.
	if err := device.startWebDriverAgent(); err != nil {
		t.Fatal(err)
	}
	if device.GetProviderState() != "preparing" || device.InitialSetupDone {
		t.Fatal("attach declared an unverified external WDA ready")
	}
	select {
	case <-device.WdaReadyChan:
		t.Fatal("attach signalled readiness without an actual WDA health response")
	default:
	}
}
