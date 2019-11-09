package poplib

import (
	"bytes"
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

func cleanResponseHeader(r []byte) []byte {
	if nil == r {
		return nil
	}

	if bytes.HasPrefix(r, prefixOk) {
		// +OK ...
		return bytes.TrimPrefix(r, prefixOk)
	} else if bytes.HasPrefix(r, prefixErr) {
		return bytes.TrimPrefix(r, prefixErr)
	}

	return r
}

type StatResult struct {
	Count uint

}