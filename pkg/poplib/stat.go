package poplib

import (
	"bytes"
	"errors"
	"strconv"
)

const (
	CommandStat = "STAT"
)

type StatResult struct {
	Count     uint64
	OctetSize uint64
}

// Stat implemented POP3's `STAT` command.
// C: STAT
// S: +OK 1 128
func Stat(c *Client) (*StatResult, error) {
	var (
		err error = nil
	)

	line, err := c.WriteCmd(FormatCommand(CommandStat), true)
	if nil != err {
		return nil, err
	}

	logger.Debug(string(line))
	return parseStatResult(line)
}

func parseStatResult(r []byte) (*StatResult, error) {
	r = TrimPrefix(r)
	s := bytes.Split(r, []byte{' '})
	if 2 != len(s) {
		return nil, errors.New("malformed response")
	}

	count, err := strconv.ParseUint(string(s[0]), 10, 64)
	if nil != err {
		return nil, err
	}
	size, err := strconv.ParseUint(string(s[1]), 10, 64)
	if nil != err {
		return nil, err
	}

	result := StatResult{
		Count:     count,
		OctetSize: size,
	}

	return &result, nil
}
