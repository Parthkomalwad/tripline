package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Parthkomalwad/tripline/internal/tripwire"
	"github.com/Parthkomalwad/tripline/internal/watcher"
)

// starterConfig is watch-only: no blocking, no sinks until you add them.
const starterConfig = `# tripline starter config. Watch-only: tripline alerts and never blocks.
watcher:
  listen: 127.0.0.1:7700
  trap_listen: 127.0.0.1:7702
  status_page: 127.0.0.1:7701
  state_dir: ./tripline-state
  rules_file: ./rules.yaml
  # Name of an env var that holds a dead man's switch ping URL.
  # heartbeat_ping_url_env: TRIPLINE_DEADMAN_URL
# Name env vars here. Never write webhook URLs in this file.
# sinks:
#   - type: slack
#     webhook_url_env: TRIPLINE_SLACK_WEBHOOK
selftest:
  interval: 1h
`

const starterRules = "# Add tripline rules here. See docs/rules.md.\n" + tripwire.DefaultRule

// cmdInit handles "tripline init [-dir .]".
func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "directory to write tripline.yaml into")
	trapURL := fs.String("trap-url", "http://127.0.0.1:7702", "base URL where attackers can reach the trap listener")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	cfgPath := filepath.Join(*dir, "tripline.yaml")
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return fail(err)
	}
	// O_EXCL makes the overwrite check and the write one atomic step.
	f, err := os.OpenFile(cfgPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return fail(fmt.Errorf("%s already exists; not overwriting", cfgPath))
	}
	if err != nil {
		return fail(err)
	}
	_, werr := io.WriteString(f, starterConfig)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fail(werr)
	}
	// Keep an existing rules file.
	rulesPath := filepath.Join(*dir, "rules.yaml")
	if _, err := os.Stat(rulesPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(rulesPath, []byte(starterRules), 0o644); err != nil {
			return fail(err)
		}
	}

	stateDir := filepath.Join(*dir, "tripline-state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fail(err)
	}
	tokens, err := watcher.LoadTokens(stateDir)
	if err != nil {
		return fail(err)
	}
	token, err := tokens.Add("default")
	if err != nil {
		return fail(err)
	}

	decoyDir := filepath.Join(*dir, "decoys")
	if err := os.MkdirAll(decoyDir, 0o700); err != nil {
		return fail(err)
	}
	decoys, err := tripwire.Generate(stateDir, *trapURL, decoyDir)
	if err != nil {
		return fail(err)
	}

	fmt.Fprintf(stdout, "Wrote %s and %s.\n", cfgPath, stateDir)
	fmt.Fprintln(stdout, "Sensor token for \"default\". Store it securely. It is shown once:")
	fmt.Fprintln(stdout, token)
	for _, d := range decoys {
		fmt.Fprintf(stdout, "Decoy %s: %s\n", d.Kind, d.Location)
	}
	fmt.Fprintln(stdout, "Next steps:")
	fmt.Fprintln(stdout, "  0. Copy the decoys to where an attacker would look. Set -trap-url to an address they can reach.")
	fmt.Fprintln(stdout, "  1. Add rules to rules.yaml.")
	fmt.Fprintln(stdout, "  2. Start the watcher with this config.")
	fmt.Fprintln(stdout, "  3. Run: tripline status -config", cfgPath)
	return 0
}
