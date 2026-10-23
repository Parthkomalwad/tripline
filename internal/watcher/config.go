package watcher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Parthkomalwad/tripline/internal/selftest"
	"gopkg.in/yaml.v3"
)

// Config is the watcher part of the one tripline config file. Secrets are
// referenced by environment variable name, never written inline.
type Config struct {
	Watcher struct {
		Listen              string `yaml:"listen"`
		TrapListen          string `yaml:"trap_listen"`
		StatusPage          string `yaml:"status_page"`
		StateDir            string `yaml:"state_dir"`
		HeartbeatPingURLEnv string `yaml:"heartbeat_ping_url_env"`
		RulesFile           string `yaml:"rules_file"`  // unsigned rules, development only
		BundleFile          string `yaml:"bundle_file"` // signed bundle, used when trust.file is set
	} `yaml:"watcher"`
	Sinks []struct {
		Type          string `yaml:"type"`
		WebhookURLEnv string `yaml:"webhook_url_env"`
		URLEnv        string `yaml:"url_env"`
	} `yaml:"sinks"`
	Trust struct {
		File               string        `yaml:"file"`
		RequiredSignatures int           `yaml:"required_signatures"`
		LooseningDelay     time.Duration `yaml:"loosening_delay"`
	} `yaml:"trust"`
	Selftest struct {
		Interval  time.Duration     `yaml:"interval"`
		Sensors   []selftest.Sensor `yaml:"sensors"`
		AllowHost string            `yaml:"allow_host"`
	} `yaml:"selftest"`
	// Sensor is read by the egress sensor, not the watcher. It is listed so
	// one config file can hold both.
	Sensor yaml.Node `yaml:"sensor"`
	Digest struct {
		Weekly string `yaml:"weekly"`
	} `yaml:"digest"`
}

// LoadConfig reads the config file, rejects unknown keys and fills defaults.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	w := &c.Watcher
	if w.Listen == "" {
		w.Listen = "127.0.0.1:7700"
	}
	if w.StatusPage == "" {
		w.StatusPage = "127.0.0.1:7701"
	}
	if w.StateDir == "" {
		return nil, errors.New("config: watcher.state_dir is required")
	}
	if c.Selftest.Interval == 0 {
		c.Selftest.Interval = time.Hour
	}
	if c.Selftest.AllowHost == "" {
		c.Selftest.AllowHost = selftest.DefaultAllowHost
	}
	return c, nil
}
