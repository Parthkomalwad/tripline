// Package lookalike flags hosts that imitate a protected domain.
package lookalike

import (
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reasons a host is flagged.
const (
	EditDistance  = "edit-distance"
	BrandOtherTLD = "brand-other-tld"
	Homoglyph     = "homoglyph"
	Punycode      = "punycode"
)

// Result names the protected domain a host imitates and why.
// Protected is empty when the only signal is an xn-- label.
type Result struct {
	Protected string
	Reason    string
}

// Load reads a protected-domains YAML file: a `domains` list.
func Load(data []byte) ([]string, error) {
	var f struct {
		Domains []string `yaml:"domains"`
	}
	err := yaml.Unmarshal(data, &f)
	return f.Domains, err
}

// IsIP reports whether host is a raw IPv4 or IPv6 address.
func IsIP(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

// ponytail: no Public Suffix List. A name ending in a 2-letter TLD whose
// second-to-last label is in this set counts as three labels (co.uk). Other
// multi-label suffixes are misread; upgrade to x/net/publicsuffix if approved.
var slds = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "edu": true, "ac": true, "or": true, "ne": true, "go": true}

// registered returns the registered domain: the last two labels, or three
// under a known 2-letter-TLD SLD.
func registered(host string) string {
	l := strings.Split(host, ".")
	n := 2
	if len(l) >= 3 && len(l[len(l)-1]) == 2 && slds[l[len(l)-2]] {
		n = 3
	}
	if len(l) <= n {
		return host
	}
	return strings.Join(l[len(l)-n:], ".")
}

// split returns the brand label and the TLD of a registered domain.
func split(reg string) (label, tld string) {
	label, tld, _ = strings.Cut(reg, ".")
	return
}

// confusables maps Cyrillic, Greek and a few Latin look-alikes to ASCII.
// ponytail: small table, not the full Unicode confusables set.
var confusables = map[rune]rune{
	'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y', // Cyrillic
	'α': 'a', 'ο': 'o', 'ι': 'i', 'ρ': 'p', 'χ': 'x', 'γ': 'y', // Greek
	'ɑ': 'a', '0': 'o', '1': 'l',
}

// skeleton decodes punycode, lowercases and folds look-alike characters.
func skeleton(label string) string {
	if p, ok := strings.CutPrefix(label, "xn--"); ok {
		if d, err := punyDecode(p); err == nil {
			label = d
		}
	}
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		if m, ok := confusables[r]; ok {
			r = m
		}
		b.WriteRune(r)
	}
	return strings.ReplaceAll(b.String(), "rn", "m")
}

// distance is the Damerau-Levenshtein distance (optimal string alignment).
func distance(a, b string) int {
	x, y := []rune(a), []rune(b)
	d := make([][]int, len(x)+1)
	for i := range d {
		d[i] = make([]int, len(y)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(x); i++ {
		for j := 1; j <= len(y); j++ {
			c := 1
			if x[i-1] == y[j-1] {
				c = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+c)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(x)][len(y)]
}

// Check reports whether host imitates one of the protected registered
// domains. The host itself, and any subdomain of a protected domain, is
// not a lookalike. Raw IPs are never lookalikes: use IsIP.
func Check(host string, protected []string) (Result, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || IsIP(host) {
		return Result{}, false
	}
	for _, p := range protected {
		p = strings.ToLower(p)
		if host == p || strings.HasSuffix(host, "."+p) {
			return Result{}, false
		}
	}
	label, tld := split(registered(host))
	sk := skeleton(label)
	for _, p := range protected {
		p = strings.ToLower(p)
		pl, ptld := split(p)
		switch {
		case label == pl && tld != ptld:
			return Result{p, BrandOtherTLD}, true
		case label != pl && sk == pl:
			return Result{p, Homoglyph}, true
		case len(pl) >= 4 && len(label) >= 4 && label != pl && distance(label, pl) <= 2:
			return Result{p, EditDistance}, true
		}
	}
	if strings.Contains(host, "xn--") {
		return Result{Reason: Punycode}, true
	}
	return Result{}, false
}
