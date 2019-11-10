package poplib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrimPrefix(t *testing.T) {
	r := []byte("+OK 1 128")
	r = TrimPrefix(r)

	assert.Equal(t, "1 128", string(r))
}
