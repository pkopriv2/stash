package sqlorg

import (
	"os"
	"testing"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
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

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("TEST"))
	if !assert.Nil(t, err) {
		return
	}

	orgn := org.NewOrg("org")
	subn := org.NewSubscription(orgn.Id, "email", 2, 1, org.Stripe, "subId", "customerId")
	memb := org.NewMember(orgn.Id, uuid.NewV1(), auth.Owner)

	assert.Nil(t, store.CreateOrg(orgn, subn, memb))
	t.Run("LoadOrgById_NotFound", func(t *testing.T) {
		_, found, err := store.LoadOrgById(uuid.NewV1())
		if err != nil {
			t.FailNow()
		}
		assert.False(t, found)
	})

	t.Run("LoadOrgById", func(t *testing.T) {
		loaded, found, err := store.LoadOrgById(orgn.Id)
		if err != nil {
			t.FailNow()
		}
		assert.True(t, found)
		assert.Equal(t, loaded, orgn)
	})

	t.Run("ListOrgs", func(t *testing.T) {
		loaded, err := store.ListOrgs(org.BuildFilter(org.FilterByOrgIds(orgn.Id)), page.Page{})
		if err != nil || len(loaded) != 1 {
			t.FailNow()
		}
		assert.Equal(t, loaded[0], orgn)
	})

}
