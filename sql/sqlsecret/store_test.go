package sqlsecret

import (
	"os"
	"testing"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/secret"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestSecretStorage(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Debug)
	defer ctx.Close()

	db, e := sql.NewSqlLiteDialer().Embed(ctx)
	if !assert.Nil(t, e) {
		return
	}

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("iron"))
	if !assert.Nil(t, err) {
		return
	}

	sec := secret.NewSecret().
		SetOrg(uuid.NewV1()).
		SetStream(uuid.NewV1(), 0).
		SetName("/name").
		MustCompile()

	t.Run("Insert", func(t *testing.T) {
		assert.Nil(t, store.SaveSecret(sec))
	})

	t.Run("Select", func(t *testing.T) {
		act, ok, err := store.LoadSecretByName(sec.OrgId, sec.Name, -1)
		if !assert.Nil(t, err) || !assert.True(t, ok) {
			return
		}
		if !assert.Equal(t, sec, act) {
			return
		}
	})

	t.Run("Insert_Stale", func(t *testing.T) {
		assert.NotNil(t, store.SaveSecret(sec))
	})

	t.Run("LoadSecrets_EmptyFilter", func(t *testing.T) {
		act, err := store.ListSecrets(sec.OrgId, secret.Filter{}, page.BuildPage())
		if !assert.Nil(t, err) {
			return
		}
		if !assert.Equal(t, 1, len(act)) {
			return
		}
		if !assert.Equal(t, sec, act[0]) {
			return
		}
	})

	// o.Run("LoadSecrets_Limit0", func(t *testing.T) {
	// limit := uint64(0)
	// act, err := store.LoadSecrets(secret.OrgId, secret.Filter{}, page.BuildPage(func(o *page.Page) {
	// o.Limit = &limit
	// }))
	// if !assert.Nil(t, err) || !assert.Equal(t, 0, len(act)) {
	// o.FailNow()
	// return
	// }
	// })
	//
	// o.Run("LoadSecrets_StartId", func(t *testing.T) {
	// next := secret.NewSecret("secret").
	// SetOrg(secret.OrgId).
	// SetGroup(secret.PolicyGroupId).
	// SetName("name2").
	// Compile()
	// if !assert.Nil(t, store.SaveSecret(next)) {
	// return
	// }
	//
	// act, err := store.LoadSecrets(secret.OrgId, secret.Filter{}, page.BuildPage(func(o *page.Page) {
	// o.AfterId = &secret.Name
	// }))
	// if !assert.Nil(t, err) {
	// return
	// }
	// if !assert.Equal(t, 1, len(act)) {
	// return
	// }
	// if !assert.Equal(t, next, act[0]) {
	// return
	// }
	// })
	//
	// o.Run("SaveAndLoadBlocks", func(t *testing.T) {
	// salt, err := crypto.Moderate.GenSalt(crypto.Rand)
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// key := salt.Apply([]byte("pass"), crypto.Moderate.Cipher().KeySize())
	//
	// streamId := uuid.NewV1()
	// stream := secret.NewStream(crypto.Rand, secret.OrgId, streamId, key, crypto.Moderate)
	//
	// block0, err := stream([]byte("block0"))
	// if !assert.Nil(t, err) {
	// return
	// }
	// block1, err := stream([]byte("block1"))
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// if !assert.Nil(t, store.SaveBlocks(block0, block1)) {
	// return
	// }
	//
	// act, err := store.LoadBlocks(secret.OrgId, streamId, 0, 128)
	// if !assert.Nil(t, err) || !assert.Equal(t, 2, len(act)) {
	// return
	// }
	//
	// assert.Equal(t, block0, act[0])
	// assert.Equal(t, block1, act[1])
	// })
}
