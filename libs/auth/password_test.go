package auth

import (
	"os"
	"testing"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/stretchr/testify/assert"
)

func TestPassword(t *testing.T) {
	login := WithPassword([]byte("password"))

	cred, _ := login()
	defer cred.Destroy()

	attmpt, err := cred.Auth(crypto.Rand)
	if !assert.Nil(t, err) {
		return
	}

	ctx := context.NewContext(os.Stdout, context.Debug)
	defer ctx.Close()

	data, err := EncodeAttempt(enc.Json, attmpt)
	if !assert.Nil(t, err) {
		return
	}

	parsed, err := DecodeAttempt(enc.Json, data)
	if !assert.Nil(t, err) {
		return
	}

	auth, err := NewAuthenticator(crypto.Rand, parsed)
	if !assert.Nil(t, err) {
		return
	}

	if !assert.Nil(t, auth.Validate(parsed)) {
		return
	}

	encoded, err := enc.Encode(enc.Json, auth)
	if !assert.Nil(t, err) {
		return
	}

	new := PasswordAuth{Typ: PasswordProtocol}
	if !assert.Nil(t, enc.Json.DecodeBinary(encoded, &new)) {
		return
	}

	if !assert.Nil(t, auth.Validate(parsed)) {
		return
	}

	if !assert.Nil(t, new.Validate(parsed)) {
		return
	}
}
