package main

import "testing"

func TestConfigValidateAllowsOptionalAdminPSK(t *testing.T) {
	cfg := &Config{
		Listen:        ":8080",
		TableName:     "wlt",
		ChainName:     "mark_traffic",
		LanInterfaces: []string{"br-lan"},
		StatePath:     "/tmp/state.json",
		DefaultPolicy: "direct",
		Policies: []Policy{
			{Name: "direct", Mark: 1, Description: "Direct"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate without admin_psk: %v", err)
	}

	cfg.AdminPSK = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate with admin_psk: %v", err)
	}
}
