package policy

import (
	"testing"

	"github.com/cott-io/stash/lang/crypto"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestPolicy_Secret_SetAndAccept(t *testing.T) {
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

	core, err := GenPolicy(crypto.Rand, orgId, acctId1, acctKey1.Public(), UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	secret, err := core.RecoverSecret(crypto.Rand, acctKey1)
	if !assert.Nil(t, err) {
		return
	}

	proxy, err := GenPolicy(crypto.Rand, orgId, acctId2, acctKey2.Public(), UserType, s)
	if !assert.Nil(t, err) {
		return
	}

	proxyKey, err := proxy.RecoverPrivateKey(crypto.Rand, acctKey2)
	if !assert.Nil(t, err) {
		return
	}

	proxyMember, err := core.AddMember(crypto.Rand, acctKey1, proxy.Id(), ProxyType, proxy.PublicKey(), Sudo)
	if !assert.Nil(t, err) {
		return
	}

	secret2, err := core.Core.RecoverSecret(crypto.Rand, proxyMember, proxyKey)
	if !assert.Nil(t, err) {
		return
	}

	assert.Equal(t, []byte(secret), []byte(secret2))
}
