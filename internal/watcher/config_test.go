package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, err := LoadConfig(write("watcher:\n  state_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Watcher.Listen != "127.0.0.1:7700" || c.Selftest.Interval != time.Hour {
		t.Errorf("defaults not set: %+v", c.Watcher)
	}
	if _, err := LoadConfig(write("watcher:\n  listen: x\n")); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Errorf("missing state_dir: %v", err)
	}
	if _, err := LoadConfig(write("watcher:\n  state_dir: x\n  slack_url: https://x\n")); err == nil {
		t.Error("unknown key accepted")
	}
}
