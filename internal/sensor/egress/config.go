package egress

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the "sensor:" section of the tripline config file.
type Config struct {
	ID             string `yaml:"id"`
	WatcherURL     string `yaml:"watcher_url"`
	TokenEnv       string `yaml:"token_env"`
	Listen         string `yaml:"listen"`
	Profile        string `yaml:"profile"`
	RulesFile      string `yaml:"rules_file"`
	StateDir       string `yaml:"state_dir"`
	BufferMaxBytes int64  `yaml:"buffer_max_bytes"`
	FailMode       string `yaml:"fail_mode"` // open (default) or closed
}

// LoadConfig reads only the "sensor:" key. Other keys belong to the watcher,
// so unknown keys are allowed in this decode.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Sensor Config `yaml:"sensor"`
	}
	if err := yaml.Unmarshal(data, &f); err != nil { // KnownFields stays off
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c := &f.Sensor
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.BufferMaxBytes == 0 {
		c.BufferMaxBytes = 50 << 20
	}
	if c.FailMode == "" {
		c.FailMode = "open"
	}
	if c.FailMode != "open" && c.FailMode != "closed" {
		return nil, fmt.Errorf("config: sensor.fail_mode must be open or closed, got %q", c.FailMode)
	}
	for _, r := range []struct{ key, val string }{
		{"id", c.ID}, {"watcher_url", c.WatcherURL}, {"token_env", c.TokenEnv},
		{"profile", c.Profile}, {"rules_file", c.RulesFile}, {"state_dir", c.StateDir},
	} {
		if r.val == "" {
			return nil, errors.New("config: sensor." + r.key + " is required")
		}
	}
	return c, nil
}
