package tripwire

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Generate plants two decoys in outDir: a fake gateway config.yaml and a
// .env.backup. Both point at the trap. It never overwrites a file.
func Generate(stateDir, trapBaseURL, outDir string) ([]Decoy, error) {
	reg, err := LoadRegistry(stateDir)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(trapBaseURL, "/")
	files := []struct{ name, kind, body string }{
		{"config.yaml", "gateway-config", "model_list:\n  - model_name: gpt-4o\n    litellm_params:\n      model: openai/gpt-4o\n      api_base: %[1]s/trap/%[2]s/v1\n      api_key: %[3]s\ngeneral_settings:\n  master_key: %[4]s\n"},
		{".env.backup", "env-backup", "OPENAI_BASE_URL=%[1]s/trap/%[2]s/v1\nOPENAI_API_KEY=%[3]s\n"},
	}
	paths := make([]string, len(files))
	for i, f := range files {
		p, err := filepath.Abs(filepath.Join(outDir, f.name))
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("%s exists: not overwriting", p)
		}
		paths[i] = p
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	var out []Decoy
	for i, f := range files {
		d, err := reg.Add(f.kind, paths[i], false)
		if err != nil {
			return out, err
		}
		fh, err := os.OpenFile(paths[i], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return out, err
		}
		_, werr := fmt.Fprintf(fh, f.body, base, d.Token, "tlfake_"+randString(24), "tlfake_"+randString(24))
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return out, werr
		}
		out = append(out, d)
	}
	return out, nil
}
