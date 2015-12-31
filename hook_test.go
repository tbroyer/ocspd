package ocspd

import (
	"bytes"
	"testing"
)

func TestRunHookCmd(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := RunHookCmd("testdata/hook.sh", []byte("ocsp-response"), &stdout, &stderr); err != nil {
		t.Error(err)
	}
	if s, want := stdout.String(), "OCSP Response updated!\n"; s != want {
		t.Errorf("RunHookCmd: got %s on stdout, want %s", s, want)
	}
	if s, want := stderr.String(), "script successfully called"; s != want {
		t.Errorf("RunHookCmd: got %s on stderr, want %s", s, want)
	}
}
