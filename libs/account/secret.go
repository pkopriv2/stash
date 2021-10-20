package account

import (
	"io"
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/secret"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

type SecretAndShard struct {
	Secret     `json:"secret"`
	LoginShard `json:"shard"`
}

// An accounts secret contains the public and private information of a account.
// Only public information is directly consumable.  Private information must
// be derived with the use of a paired login shard, which is encrypted using
// a credential.
type Secret struct {
	AccountId uuid.UUID          `json:"account_id"`
	Version   int                `json:"version"`
	Created   time.Time          `json:"created"`
	Updated   time.Time          `json:"updated"`
	Public    secret.PublicShard `json:"public_shard"`
	Chain     secret.KeyChain    `json:"chain"`
}

func NewSecret(rand io.Reader, id uuid.UUID, creds auth.Credential, strength crypto.Strength) (ret Secret, shard LoginShard, err error) {
	sec, err := secret.GenSecret(rand, strength)
	if err != nil {
		return
	}
	defer crypto.Destroy(sec)

	pub, shard, err := NewLoginPair(rand, enc.Json, id, sec, creds, strength)
	if err != nil {
		return
	}

	chain, key, seed, err := secret.NewKeyChain(rand, enc.Json, sec, strength)
	if err != nil {
		return
	}
	defer crypto.Destroy(key)
	defer crypto.Destroy(seed)

	now := time.Now().UTC()
	ret = Secret{id, 0, now, now, pub, chain}
	return
}

func (m Secret) ValidateSecret(secret secret.Secret) (err error) {
	seed, err := m.UnlockSeed(secret)
	defer crypto.Destroy(seed)
	return
}

func (m Secret) DeriveSecret(cred auth.Credential, priv LoginShard) (secret.Secret, error) {
	return priv.Derive(enc.Json, cred, m.Public)
}

func (m Secret) UnlockKey(secret secret.Secret) (crypto.PrivateKey, error) {
	return m.Chain.ExtractKey(enc.Json, secret)
}

func (m Secret) UnlockSeed(secret secret.Secret) (crypto.Bytes, error) {
	return m.Chain.ExtractSeed(enc.Json, secret)
}

func (m Secret) NewShard(rand io.Reader, secret secret.Secret, cred auth.Credential) (ret LoginShard, err error) {
	if err = m.ValidateSecret(secret); err != nil {
		return
	}
	shard, err := secret.Shard(rand)
	if err != nil {
		return
	}
	defer crypto.Destroy(shard)
	ret, err = NewLoginShard(rand, enc.Json, m.AccountId, shard, cred, m.Public.Strength)
	return
}
