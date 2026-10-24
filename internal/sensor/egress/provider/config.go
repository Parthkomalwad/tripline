package provider

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
)

// Key says where one provider key lives. Set exactly one of KeyFile, KeyEnv.
type Key struct {
	KeyFile      string `yaml:"key_file"`
	KeyEnv       string `yaml:"key_env"`
	Organization string `yaml:"organization"` // openai only: OpenAI-Organization
	Project      string `yaml:"project"`      // openai only: OpenAI-Project
}

// Providers is the "sensor.providers" section. A nil entry means the
// provider is not served (404).
type Providers struct {
	Anthropic *Key `yaml:"anthropic"`
	OpenAI    *Key `yaml:"openai"`
}

// Any reports whether at least one provider is configured.
func (p Providers) Any() bool { return p.Anthropic != nil || p.OpenAI != nil }

// load reads the key once. The caller keeps it in memory only. A key file
// that group or others can read gets a warning (not on Windows).
func (k *Key) load(name string, log *slog.Logger) (string, error) {
	if (k.KeyFile == "") == (k.KeyEnv == "") {
		return "", fmt.Errorf("providers.%s: set exactly one of key_file, key_env", name)
	}
	if name == "anthropic" && (k.Organization != "" || k.Project != "") {
		return "", errors.New("providers.anthropic: organization and project are not supported")
	}
	var v string
	if k.KeyEnv != "" {
		v = os.Getenv(k.KeyEnv)
	} else {
		b, err := os.ReadFile(k.KeyFile)
		if err != nil {
			return "", fmt.Errorf("providers.%s: %w", name, err)
		}
		v = string(b)
		if st, err := os.Stat(k.KeyFile); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
			log.Warn("provider key file is readable by group or others", "provider", name, "file", k.KeyFile, "mode", st.Mode().Perm().String())
		}
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", fmt.Errorf("providers.%s: key is empty", name)
	}
	return v, nil
}
