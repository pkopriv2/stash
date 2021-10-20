package secret

import (
	"testing"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/stretchr/testify/assert"
)

func TestShardEncoding(t *testing.T) {
	secret, err := GenSecret(crypto.Rand, crypto.Minimal)
	if !assert.Nil(t, err) {
		return
	}

	shard, err := secret.Shard(crypto.Rand)
	if !assert.Nil(t, err) {
		return
	}

	bytes, err := EncodeShard(enc.Json, shard)
	if !assert.Nil(t, err) {
		return
	}

	parsed, err := DecodeShard(enc.Json, bytes)
	if !assert.Nil(t, err) {
		return
	}

	assert.Equal(t, shard, parsed)
}
