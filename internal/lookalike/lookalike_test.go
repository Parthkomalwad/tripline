package lookalike

import (
	"os"
	"slices"
	"testing"
)

func protected(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../rules/core/protected-domains.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(data)
	if err != nil || len(p) == 0 {
		t.Fatalf("load: %v, %d domains", err, len(p))
	}
	return p
}

func TestCheck(t *testing.T) {
	p := protected(t)
	tests := []struct {
		host, protected, reason string // empty reason: no hit
	}{
		{"litellm.dev", "litellm.ai", BrandOtherTLD},
		{"github.co", "github.com", BrandOtherTLD},
		{"anthrop1c.com", "anthropic.com", EditDistance},
		{"anthroplc.com", "anthropic.com", EditDistance},
		{"anthropci.com", "anthropic.com", EditDistance}, // transposition
		// Cyrillic a: xn--nthropic-06g.com.
		{"xn--nthropic-06g.com", "anthropic.com", Homoglyph},
		{"XN--NTHROPIC-06G.COM.", "anthropic.com", Homoglyph},
		{"rnicrosoft.com", "", ""}, // not protected
		{"githubusercontent.co", "githubusercontent.com", BrandOtherTLD},
		{"xn--hxajbheg2az3al.example", "", Punycode}, // punycode alone
		// Documented behavior.
		{"anthropic-api.com", "", ""},          // distance 4: not flagged
		{"pypi.org.evil.com", "", ""},          // registered domain is evil.com
		{"pyp.org", "", ""},                    // label shorter than 4: no distance check
		{"pypo.org", "pypi.org", EditDistance}, // 4 letters is the floor
		{"api.anthropic.com", "", ""},          // subdomain of protected
		{"sub.openai.com", "", ""},             // subdomain of protected
		{"anthropic.com", "", ""},              // exact
		{"files.pythonhosted.org", "", ""},     // subdomain
		{"registry.npmjs.org", "", ""},         // subdomain
		{"docs.litellm.ai", "", ""},            // subdomain
		{"example.co.uk", "", ""},              // three-label registered domain
		{"10.0.0.1", "", ""},                   // IPs are not lookalikes
		{"", "", ""},                           //
		{"openai.com.attacker.co.uk", "", ""},  // registered domain attacker.co.uk
	}
	for _, tt := range tests {
		r, ok := Check(tt.host, p)
		if ok != (tt.reason != "") || r.Reason != tt.reason || r.Protected != tt.protected {
			t.Errorf("Check(%q) = %+v, %v; want %s %s", tt.host, r, ok, tt.protected, tt.reason)
		}
	}
}

func TestRegistered(t *testing.T) {
	for in, want := range map[string]string{
		"a.b.example.com": "example.com", "example.com": "example.com", "com": "com",
		"x.example.co.uk": "example.co.uk", "foo.co.uk": "foo.co.uk", "github.co": "github.co",
		"a.huggingface.co": "huggingface.co", "x.y.com.au": "y.com.au",
	} {
		if got := registered(in); got != want {
			t.Errorf("registered(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsIP(t *testing.T) {
	for host, want := range map[string]bool{
		"1.2.3.4": true, "::1": true, "[2001:db8::1]": true, "example.com": false, "1.2.3": false, "": false,
	} {
		if got := IsIP(host); got != want {
			t.Errorf("IsIP(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDistance(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
	}{{"abc", "abc", 0}, {"abcd", "abdc", 1}, {"kitten", "sitting", 3}, {"", "ab", 2}} {
		if got := distance(tt.a, tt.b); got != tt.want {
			t.Errorf("distance(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestPunyDecode(t *testing.T) {
	// RFC 3492 section 7.1 samples.
	tests := []struct{ in, want string }{
		{"egbpdaj6bu4bxfgehfvwxn", "ليهمابتكلموشعربي؟"},
		{"ihqwcrb4cv8a8dqg056pqjye", "他们为什么不说中文"},
		{"ihqwctvzc91f659drss3x8bo0yb", "他們爲什麽不說中文"},
		{"Proprostnemluvesky-uyb24dma41a", "Pročprostěnemluvíčesky"},
		{"4dbcagdahymbxekheh6e0a7fei0b", "למההםפשוטלאמדבריםעברית"},
		{"nthropic-06g", "аnthropic"},
	}
	for _, tt := range tests {
		got, err := punyDecode(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("punyDecode(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"aé-b", "!!", "zzzzzzzzzzzzzzzzzzzz"} {
		if _, err := punyDecode(bad); err == nil {
			t.Errorf("punyDecode(%q): want error", bad)
		}
	}
}

func TestLoadListContainsRegisteredDomains(t *testing.T) {
	p := protected(t)
	for _, d := range []string{"anthropic.com", "pythonhosted.org", "litellm.ai"} {
		if !slices.Contains(p, d) {
			t.Errorf("missing %s", d)
		}
	}
}
