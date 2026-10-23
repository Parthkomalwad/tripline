package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"version"}, 0, "tripline dev\n"},
		{nil, 2, ""},
		{[]string{"nope"}, 2, ""},
	}
	for _, tc := range tests {
		var stdout, stderr bytes.Buffer
		code := run(tc.args, &stdout, &stderr)
		if code != tc.code || stdout.String() != tc.out {
			t.Errorf("run(%v) = %d %q, want %d %q", tc.args, code, stdout.String(), tc.code, tc.out)
		}
		if code != 0 && !strings.Contains(stderr.String(), "tripline") {
			t.Errorf("run(%v) stderr = %q, want usage or error", tc.args, stderr.String())
		}
	}
}
