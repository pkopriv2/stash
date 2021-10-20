package auth

import (
	"testing"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/stretchr/testify/assert"
)

func TestSigningAuth(t *testing.T) {
	key, err := crypto.GenRSAKey(crypto.Rand, 1024)
	if !assert.Nil(t, err) {
		return
	}

	login := WithSignature(key, crypto.Moderate)

	cred, _ := login()
	defer cred.Destroy()

	attmpt, err := cred.Auth(crypto.Rand)
	if !assert.Nil(t, err) {
		return
	}
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

	encoding, err := enc.Encode(enc.Json, auth)
	if !assert.Nil(t, err) {
		return
	}

	new := SignatureAuth{typ: SignatureProtocol}
	if !assert.Nil(t, enc.Json.DecodeBinary(encoding, &new)) {
		return
	}

	if !assert.Nil(t, auth.Validate(parsed)) {
		return
	}

	if !assert.Nil(t, new.Validate(parsed)) {
		return
	}

	// t.Run("Authenticator_BadType", func(t *testing.T) {
	// if !assert.NotNil(t, auth.Validate(enc.DefaultRegistry, AuthAttempt{AuthVal: "pass"})) {
	// return
	// }
	// })
	//
	// t.Run("Authenticator_Pass", func(t *testing.T) {
	// if !assert.Nil(t, auth.Validate(enc.DefaultRegistry, attmpt)) {
	// return
	// }
	// })
	//
	// t.Run("Auth_DifferentKey", func(t *testing.T) {
	// cred1, _ := login()
	// defer cred1.Destroy()
	//
	// key2, err := crypto.GenRsaKey(crypto.Rand, 1024)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// login2 := WithSignature(key2, teams.Moderate)
	//
	// cred2, _ := login2()
	// defer cred2.Destroy()
	//
	// auth1, err := cred1.Auth(crypto.Rand, enc.Gob)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// auth2, err := cred2.Auth(crypto.Rand, enc.Gob)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// assert.NotEqual(t, auth1, auth2)
	// })
	//
	// t.Run("Auth_SameKey", func(t *testing.T) {
	// cred, _ := login()
	// defer cred.Destroy()
	//
	// auth1, err := cred.Auth(crypto.Rand, enc.Gob)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// auth2, err := cred.Auth(crypto.Rand, enc.Gob)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// assert.NotEqual(t, auth1, auth2)
	// })
	//
	// t.Run("Hash_Consistency", func(t *testing.T) {
	// cred, _ := login()
	// defer cred.Destroy()
	//
	// salt, err := crypto.GenSalt(crypto.Rand)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// hash1, err := cred.Hash(salt, 32)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// for i := 0; i < 100; i++ {
	// hashi, err := cred.Hash(salt, 32)
	// if !assert.Nil(t, err) || !assert.True(t, hash1.Equals(hashi)) {
	// return
	// }
	// }
	// })
}
