package internal

import (
	"bytes"
	"io"
	"os/exec"
)

// RunHookCmd runs the given command/executable,
// sending it a serialized ocsp response on the standard input.
//
// Standard output and standard error are piped into the passed in writers.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status
func RunHookCmd(hookCmd string, resp []byte, stdout, stderr io.Writer) error {
	cmd := exec.Command(hookCmd)
	cmd.Stdin = bytes.NewReader(resp)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
