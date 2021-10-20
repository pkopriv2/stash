package account

import (
	"testing"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/secret"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func Account_ByLogin(login auth.Login) func(t *testing.T) {
	return func(t *testing.T) {
		creds, _ := login()
		defer creds.Destroy()

		member, shard, err := NewSecret(crypto.Rand, uuid.NewV1(), creds, crypto.Minimal)
		if !assert.Nil(t, err) {
			return
		}

		var secret secret.Secret
		if !t.Run("DeriveSecret", func(t *testing.T) {
			secret, err = member.DeriveSecret(creds, shard)
			assert.Nil(t, err)
		}) {
			return
		}

		t.Run("UnlockKey", func(t *testing.T) {
			_, err := member.UnlockKey(secret)
			assert.Nil(t, err)
		})

		t.Run("UnlockSeed", func(t *testing.T) {
			_, err := member.UnlockSeed(secret)
			assert.Nil(t, err)
		})
	}
}

func TestAccount(t *testing.T) {
	owner, err := crypto.GenRSAKey(crypto.Rand, 1024)
	if !assert.Nil(t, err) {
		return
	}

	t.Run("ExtractCreds_NoCredential", func(t *testing.T) {
		_, e := auth.ExtractCreds(func() (auth.Credential, error) {
			return nil, nil
		})
		assert.NotNil(t, e)
	})

	t.Run("NewAccount_WithSigner", Account_ByLogin(auth.WithSignature(owner, crypto.Moderate)))
	t.Run("NewAccount_WithPassword", Account_ByLogin(auth.WithPassword([]byte("pass"))))
}
