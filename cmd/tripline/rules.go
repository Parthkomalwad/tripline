package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Parthkomalwad/tripline/internal/bundle"
)

// keyFile is the on-disk form of a generated key. Private files hold the
// 32-byte seed; public files hold the public key.
type keyFile struct {
	KeyID      string `yaml:"key_id"`
	PrivateKey string `yaml:"private_key,omitempty"`
	PublicKey  string `yaml:"public_key,omitempty"`
}

// cmdRules handles "tripline rules keygen|sign|verify|diff".
func cmdRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: tripline rules keygen|sign|verify|diff")
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = rulesKeygen(args[1:], stdout, stderr)
	case "sign":
		err = rulesSign(args[1:], stdout, stderr)
	case "verify":
		err = rulesVerify(args[1:], stdout, stderr)
	case "diff":
		err = rulesDiff(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tripline rules: unknown subcommand %q\n", args[0])
		return 2
	}
	switch err {
	case nil:
		return 0
	case flag.ErrHelp, errUsage:
		return 2
	}
	fmt.Fprintln(stderr, err)
	return 1
}

var errUsage = fmt.Errorf("usage")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func rulesKeygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("rules keygen", stderr)
	id := fs.String("id", "", "key id, for example maya-2026")
	out := fs.String("out", ".", "output directory")
	owner := fs.String("owner", "", "owner name for the trust snippet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || filepath.Base(*id) != *id {
		fmt.Fprintln(stderr, "keygen: -id is required and must not contain a path")
		return errUsage
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := writeYAML(filepath.Join(*out, *id+".key"), keyFile{KeyID: *id, PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed())}, 0o600); err != nil {
		return err
	}
	if err := writeYAML(filepath.Join(*out, *id+".pub"), keyFile{KeyID: *id, PublicKey: pubB64}, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Add this to the trust file:\n  - key_id: %s\n    public_key: %s\n    owner: %s\n", *id, pubB64, *owner)
	return nil
}

func writeYAML(path string, v any, perm os.FileMode) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	// O_EXCL: never overwrite a key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readPrivate(path string) (string, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var k keyFile
	if err := yaml.Unmarshal(data, &k); err != nil {
		return "", nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(k.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize || k.KeyID == "" {
		return "", nil, fmt.Errorf("%s: not a tripline private key file", path)
	}
	return k.KeyID, ed25519.NewKeyFromSeed(seed), nil
}

func rulesSign(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("rules sign", stderr)
	key := fs.String("key", "", "private key file")
	in := fs.String("in", "", "bundle file, updated in place")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *in == "" {
		fmt.Fprintln(stderr, "sign: -key and -in are required")
		return errUsage
	}
	id, priv, err := readPrivate(*key)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	b, err := bundle.Parse(data)
	if err != nil {
		return err
	}
	if err := b.Sign(id, priv); err != nil {
		return err
	}
	out, err := b.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*in, out, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s as %s (%d signatures)\n", *in, id, len(b.Signatures))
	return nil
}

func rulesVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("rules verify", stderr)
	trustPath := fs.String("trust", "", "trust file")
	current := fs.Int("current", 0, "currently applied bundle version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustPath == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: tripline rules verify -trust trust.yaml [-current N] bundle.yaml")
		return errUsage
	}
	trust, err := bundle.LoadTrust(*trustPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var applied *bundle.Applied
	if *current > 0 {
		applied = &bundle.Applied{Version: *current}
	}
	_, o := bundle.Check(data, trust, applied, time.Now())
	printChanges(stdout, o.Changes)
	if !o.Accepted {
		return fmt.Errorf("rejected: %s: %s", o.Reason, o.Detail)
	}
	state := "effective now"
	if o.Pending {
		state = "pending: takes effect later"
	}
	fmt.Fprintf(stdout, "ok: version %d, %s\n", o.Version, state)
	return nil
}

func rulesDiff(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("rules diff", stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: tripline rules diff old.yaml new.yaml")
		return errUsage
	}
	var bs [2]*bundle.Bundle
	for i := range bs {
		data, err := os.ReadFile(fs.Arg(i))
		if err != nil {
			return err
		}
		if bs[i], err = bundle.Parse(data); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(i), err)
		}
	}
	changes := bundle.Diff(bs[0].Rules, bs[1].Rules)
	printChanges(stdout, changes)
	if len(changes) == 0 {
		fmt.Fprintln(stdout, "no rule changes")
	}
	return nil
}

func printChanges(w io.Writer, cs []bundle.Change) {
	for _, c := range cs {
		fmt.Fprintf(w, "%-7s %s: %s\n", c.Dir, c.RuleID, c.Detail)
	}
}
