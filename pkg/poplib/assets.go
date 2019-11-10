package poplib

import (
	"bytes"
	"fmt"
)

const (
	// CRLF is the line-ending.
	CRLF = "\r\n"
)

func FormatCommand(base string, args ...string) []byte {
	cmd := base
	for _, i := range args {
		cmd += fmt.Sprintf(" %s", i)
	}

	cmd += CRLF
	return []byte(cmd)
}

// TrimPrefix removes the "+OK<space>" prefix from
// response line.
func TrimPrefix(v []byte) []byte {
	r := bytes.TrimPrefix(v, prefixOk)
	r = bytes.Trim(r, " ")
	return r
}
