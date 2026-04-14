package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Policy struct {
	Name        string `json:"name"`
	Mark        uint32 `json:"mark"`
	Description string `json:"description"`
}

type Config struct {
	Listen        string   `json:"listen"`
	TableName     string   `json:"table_name"`
	ChainName     string   `json:"chain_name"`
	LanInterfaces []string `json:"lan_interfaces"`
	CreateTable   bool     `json:"create_table"`
	ChainPriority int32    `json:"chain_priority"`
	CleanupOnExit bool     `json:"cleanup_on_exit"`
	StatePath     string   `json:"state_path"`
	AdminPSK      string   `json:"admin_psk"`
	DefaultPolicy string   `json:"default_policy"`
	Policies      []Policy `json:"policies"`
	TrafficAPIURL string   `json:"traffic_api_url"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.TableName == "" {
		return fmt.Errorf("table_name is required")
	}
	if c.ChainName == "" {
		return fmt.Errorf("chain_name is required")
	}

	if len(c.LanInterfaces) == 0 {
		return fmt.Errorf("lan_interfaces must be non-empty")
	}

	if len(c.Policies) == 0 {
		return fmt.Errorf("at least one policy is required")
	}

	names := make(map[string]bool)
	marks := make(map[uint32]bool)
	for _, p := range c.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy name is required")
		}
		if names[p.Name] {
			return fmt.Errorf("duplicate policy name: %s", p.Name)
		}
		names[p.Name] = true

		if p.Mark == 0 {
			return fmt.Errorf("policy mark must be non-zero for policy %q", p.Name)
		}
		if marks[p.Mark] {
			return fmt.Errorf("duplicate policy mark: %d", p.Mark)
		}
		marks[p.Mark] = true
	}

	if !names[c.DefaultPolicy] {
		return fmt.Errorf("default_policy %q not found in policies", c.DefaultPolicy)
	}

	return nil
}

func (c *Config) PolicyByName(name string) *Policy {
	for i := range c.Policies {
		if c.Policies[i].Name == name {
			return &c.Policies[i]
		}
	}
	return nil
}
