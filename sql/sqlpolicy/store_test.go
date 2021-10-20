package sqlpolicy

import (
	"os"
	"testing"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestPolicyStore_DirectMember(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Debug)

	db, e := sql.NewSqlLiteDialer().Embed(ctx)
	if !assert.Nil(t, e) {
		return
	}

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("iron"))
	if !assert.Nil(t, err) {
		return
	}

	s := crypto.Moderate

	orgId, acctId1 :=
		uuid.NewV1(), uuid.NewV1()

	acctKey1, err := s.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		return
	}

	core, err := policy.GenPolicy(crypto.Rand, orgId, acctId1, acctKey1.Public(), policy.UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	if !assert.Nil(t, store.SavePolicy(core.Core, core.CoreMember)) {
		return
	}

	lock, ok, err := store.LoadPolicyLock(orgId, core.Id(), acctId1)
	if !assert.Nil(t, err) || !assert.True(t, ok) {
		return
	}

	secretExp, err := core.RecoverSecret(crypto.Rand, acctKey1)
	if !assert.Nil(t, err) {
		return
	}

	secretAct, err := lock.RecoverSecret(crypto.Rand, acctKey1)
	if !assert.Nil(t, err) {
		return
	}

	assert.Equal(t, []byte(secretExp), []byte(secretAct))
}

func TestPolicyStore_ProxyMember(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Debug)

	db, e := sql.NewSqlLiteDialer().Embed(ctx)
	if !assert.Nil(t, e) {
		return
	}

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("iron"))
	if !assert.Nil(t, err) {
		return
	}

	s := crypto.Moderate

	orgId, acctId1, acctId2 :=
		uuid.NewV1(), uuid.NewV1(), uuid.NewV1()

	acctKey1, err := s.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		return
	}
	acctKey2, err := s.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		return
	}

	core, err := policy.GenPolicy(crypto.Rand, orgId, acctId1, acctKey1.Public(), policy.UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	proxy, err := policy.GenPolicy(crypto.Rand, orgId, acctId2, acctKey2.Public(), policy.UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	proxyMember, err := core.AddMember(crypto.Rand, acctKey1, proxy.Id(), policy.ProxyType, proxy.PublicKey())
	if !assert.Nil(t, err) {
		return
	}

	if !assert.Nil(t, store.SavePolicy(core.Core, core.CoreMember)) {
		return
	}
	if !assert.Nil(t, store.SavePolicy(proxy.Core, proxy.CoreMember)) {
		return
	}
	if !assert.Nil(t, store.SavePolicyMember(proxyMember)) {
		return
	}

	lock, ok, err := store.LoadPolicyLock(orgId, core.Id(), acctId2)
	if !assert.Nil(t, err) || !assert.True(t, ok) {
		return
	}

	secretExp, err := core.RecoverSecret(crypto.Rand, acctKey1)
	if !assert.Nil(t, err) {
		return
	}

	secretAct, err := lock.RecoverSecret(crypto.Rand, acctKey2)
	if !assert.Nil(t, err) {
		return
	}

	assert.Equal(t, []byte(secretExp), []byte(secretAct))
}

func TestPolicyStore_Proxy2Member(t *testing.T) {
	ctx := context.NewContext(os.Stdout, context.Debug)

	db, e := sql.NewSqlLiteDialer().Embed(ctx)
	if !assert.Nil(t, e) {
		return
	}

	store, err := NewSqlStore(db, sql.NewSchemaRegistry("iron"))
	if !assert.Nil(t, err) {
		return
	}

	s := crypto.Moderate

	orgId, acctId1, acctId2 :=
		uuid.NewV1(), uuid.NewV1(), uuid.NewV1()

	acctKey1, err := s.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		return
	}
	acctKey2, err := s.GenKey(crypto.Rand, crypto.RSA)
	if !assert.Nil(t, err) {
		return
	}

	core, err := policy.GenPolicy(crypto.Rand, orgId, acctId1, acctKey1.Public(), policy.UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	proxy2, err := policy.GenPolicy(crypto.Rand, orgId, acctId2, acctKey2.Public(), policy.UserType, s, "another thing")
	if !assert.Nil(t, err) {
		return
	}

	proxy1, err := policy.GenPolicy(crypto.Rand, orgId, proxy2.Id(), proxy2.PublicKey(), policy.UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	proxy1Member, err := core.AddMember(crypto.Rand, acctKey1, proxy1.Id(), policy.ProxyType, proxy1.PublicKey(), "something")
	if !assert.Nil(t, err) {
		return
	}

	if !assert.Nil(t, store.SavePolicy(core.Core, core.CoreMember)) {
		return
	}
	if !assert.Nil(t, store.SavePolicy(proxy2.Core, proxy2.CoreMember)) {
		return
	}
	if !assert.Nil(t, store.SavePolicy(proxy1.Core, proxy1.CoreMember)) {
		return
	}
	if !assert.Nil(t, store.SavePolicyMember(proxy1Member)) {
		return
	}

	lock, ok, err := store.LoadPolicyLock(orgId, core.Id(), acctId2)
	if !assert.Nil(t, err) || !assert.True(t, ok) {
		return
	}

	secretExp, err := core.RecoverSecret(crypto.Rand, acctKey1)
	if !assert.Nil(t, err) {
		return
	}

	secretAct, err := lock.RecoverSecret(crypto.Rand, acctKey2)
	if !assert.Nil(t, err) {
		return
	}

	assert.Equal(t, []byte(secretExp), []byte(secretAct))
	//
	// actions, err := store.LoadEnabledActions(orgId, acctId2, core.Id())
	// if !assert.Nil(t, err) {
	// return
	// }
	//
	// fmt.Println(enc.Json.MustEncode(actions))
}
