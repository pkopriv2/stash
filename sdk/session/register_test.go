package session

import (
	"os"
	"testing"

	"github.com/cott-io/stash/http/server/httptest"
	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/libs/auth"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Info)
	defer ctx.Close()

	server, err := httptest.StartDefaultServer(ctx)
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}
	defer server.Close()

	key, err := crypto.Moderate.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	err = Register(ctx,
		auth.ByKey(key.Public()),
		auth.WithSignature(key, crypto.Moderate),
		WithClient(server.Connect()))
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	s, err := Authenticate(ctx,
		auth.ByKey(key.Public()),
		auth.WithSignature(key, crypto.Moderate),
		WithClient(server.Connect()))
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	secret, err := s.Secret().DeriveSecret()
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	token, err := s.FetchToken()
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	loaded, _, err := s.Options().Accounts().LoadPublicKey(token, s.AccountId())
	if !assert.Nil(t, err) || !assert.NotNil(t, loaded) {
		t.FailNow()
		return
	}

	pass := auth.WithPassword([]byte("password"))

	cred, err := auth.ExtractCreds(pass)
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	attmpt, err := cred.Auth(crypto.Rand)
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	shard, err := s.Secret().NewLoginShard(cred)
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	if !assert.Nil(t, s.Options().Accounts().LoginRegister(token, s.AccountId(), attmpt, shard)) {
		t.FailNow()
		return
	}

	s2, err := Authenticate(ctx,
		auth.ByKey(key.Public()),
		pass,
		WithClient(server.Connect()))
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	s2Secret, err := s2.Secret().DeriveSecret()
	if !assert.Nil(t, err) {
		t.FailNow()
		return
	}

	assert.Equal(t, secret, s2Secret)

}
