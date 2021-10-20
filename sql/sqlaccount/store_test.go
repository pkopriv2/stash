package sqlaccount

import (
	"fmt"
	"os"
	"testing"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestAccountStore(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Debug)

	db, e := sql.NewSqlLiteDialer().Embed(ctx)
	if !assert.Nil(t, e) {
		return
	}

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("iron"))
	if !assert.Nil(t, err) {
		return
	}

	cred, _ := auth.ExtractCreds(auth.WithPassword([]byte("pass")))

	attmpt, err := cred.Auth(crypto.Rand)
	if !assert.Nil(t, err) {
		return
	}

	login, err := account.NewLogin(enc.Json, uuid.NewV4(), attmpt)
	if !assert.Nil(t, err) {
		return
	}

	identity, err := account.NewIdentity(login.AccountId, auth.ByUser("user"), nil, auth.IdentityOptions{})
	if !assert.Nil(t, err) {
		return
	}

	secret, shard, err := account.NewSecret(crypto.Rand, login.AccountId, cred, crypto.Moderate)
	if !assert.Nil(t, err) {
		return
	}

	assert.Nil(t, store.CreateAccount(identity, login, secret, shard, account.NewSettings(login.AccountId)))
	t.Run("LoadIdentity_NotFound", func(t *testing.T) {
		_, found, err := store.LoadIdentity(auth.ByUser("noexist"))
		if err != nil {
			t.FailNow()
		}
		assert.False(t, found)
	})

	t.Run("LoadIdentity", func(t *testing.T) {
		loaded, found, err := store.LoadIdentity(auth.ByUser("user"))
		if err != nil {
			t.FailNow()
		}
		assert.True(t, found)
		assert.Equal(t, identity, loaded)
	})

	t.Run("ListIdentities", func(t *testing.T) {
		loaded, err := store.ListIdentities(login.AccountId, util.BuildPage(util.Limit(100)))
		if err != nil {
			t.FailNow()
		}
		assert.Equal(t, 1, len(loaded))
		assert.Equal(t, identity, loaded[0])
	})

	t.Run("LoadLogin_NotFound", func(t *testing.T) {
		_, found, err := store.LoadLogin(login.AccountId, "noexist")
		if err != nil {
			t.FailNow()
		}
		assert.False(t, found)
	})

	t.Run("LoadLogin", func(t *testing.T) {
		loaded, found, err := store.LoadLogin(login.AccountId, auth.PasswordUri)
		if err != nil {
			t.FailNow()
		}
		assert.True(t, found)
		assert.Equal(t, login, loaded)
	})

	t.Run("LoadSecret_NotFound", func(t *testing.T) {
		_, found, err := store.LoadSecret(uuid.NewV4())
		if err != nil {
			t.FailNow()
		}
		assert.False(t, found)
	})

	t.Run("LoadLogin", func(t *testing.T) {
		loaded, found, err := store.LoadSecret(login.AccountId)
		if err != nil {
			t.FailNow()
		}
		assert.True(t, found)
		assert.Equal(t, secret, loaded)
	})

	t.Run("ListIdentities", func(t *testing.T) {
		loaded, err := store.ListIdentitiesByIds([]uuid.UUID{login.AccountId})
		if err != nil {
			t.FailNow()
		}
		fmt.Println(loaded)
	})
}
