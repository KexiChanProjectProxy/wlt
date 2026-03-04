package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type DeviceState struct {
	MAC      string    `json:"mac"`
	IPv4s    []string  `json:"ipv4s"`
	IPv6s    []string  `json:"ipv6s"`
	Policy   string    `json:"policy"`
	LastSeen time.Time `json:"last_seen"`
}

type State struct {
	mu      sync.RWMutex
	Devices map[string]*DeviceState `json:"devices"`
}

func NewState() *State {
	return &State{
		Devices: make(map[string]*DeviceState),
	}
}

func LoadState(path string) (*State, error) {
	s := NewState()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("open state: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(s); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}

	if s.Devices == nil {
		s.Devices = make(map[string]*DeviceState)
	}

	return s, nil
}

func (s *State) Save(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp := path + ".tmp"
	f, err := os.CreateTemp(filepath.Dir(path), "wlt-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	defer func() {
		f.Close()
		os.Remove(tmpName)
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encode state: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename state file: %w", err)
	}
	_ = tmp

	return nil
}

func (s *State) Get(mac string) *DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Devices[mac]
}

func (s *State) Set(dev *DeviceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Devices[dev.MAC] = dev
}

func (s *State) All() []*DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*DeviceState, 0, len(s.Devices))
	for _, d := range s.Devices {
		result = append(result, d)
	}
	return result
}
