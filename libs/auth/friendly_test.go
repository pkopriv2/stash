package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFriendly_Empty(t *testing.T) {
	_, err := ParseFriendlyIdentity("")
	assert.NotNil(t, err)
}
