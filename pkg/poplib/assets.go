package poplib

import (
	"errors"
)

var (
	// CRLF -> "\r\n"
	CRLF = []byte("\r\n")
)

func cleanCmd(cmd []byte) ([]byte, error) {
	if nil == cmd || 0 >= len(cmd) {
		return nil, errors.New("cmd is nil")
	}

	cmd = append(cmd, CRLF...)
	return cmd, nil
}
