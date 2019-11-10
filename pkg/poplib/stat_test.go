package poplib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStatResult(t *testing.T) {
	r := []byte("+OK 1 128")
	result, err := parseStatResult(r)

	assert.NoError(t, err)
	assert.Equal(t, uint64(1), result.Count)
	assert.Equal(t, uint64(128), result.OctetSize)
}
