package account

import (
	"io"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/secret"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

func UpdateShardVersion(version int) func(*LoginShard) {
	return func(l *LoginShard) {
		l.Version = version
	}
}

type LoginShard struct {
	AccountId uuid.UUID           `json:"account_id"`
	Uri       string              `json:"uri"`
	Version   int                 `json:"version"`
	Private   secret.PrivateShard `json:"private"`
	Salt      crypto.Salt         `json:"salt"`
}

func NewLoginPair(rand io.Reader, enc enc.Encoder, accountId uuid.UUID, sec secret.Secret, cred auth.Credential, strength crypto.Strength) (pub secret.PublicShard, priv LoginShard, err error) {
	salt, err := strength.GenSalt(rand)
	if err != nil {
		return
	}

	pass, err := cred.Salt(salt, len(salt.Nonce))
	if err != nil {
		return
	}
	defer crypto.Destroy(pass)

	pub, tmp, err := secret.NewSecretPair(rand, enc, sec, pass, strength)
	if err != nil {
		return
	}

	priv = LoginShard{
		AccountId: accountId,
		Uri:       cred.Uri(),
		Private:   tmp,
		Salt:      salt}
	return
}

func NewLoginShard(rand io.Reader, enc enc.Encoder, accountId uuid.UUID, shard secret.Shard, cred auth.Credential, strength crypto.Strength) (ret LoginShard, err error) {
	salt, err := crypto.GenSalt(rand, strength.SaltOptions())
	if err != nil {
		return
	}

	key, err := cred.Salt(salt, len(salt.Nonce))
	if err != nil {
		return
	}
	defer key.Destroy()

	priv, err := secret.EncryptShard(rand, enc, shard, key, strength)
	if err != nil {
		return
	}

	ret = LoginShard{
		AccountId: accountId,
		Uri:       cred.Uri(),
		Private:   priv,
		Salt:      salt}
	return
}

func (m LoginShard) Decrypt(dec enc.Decoder, cred auth.Credential) (ret secret.Shard, err error) {
	key, err := cred.Salt(m.Salt, len(m.Salt.Nonce))
	if err != nil {
		return
	}
	defer key.Destroy()
	return m.Private.Decrypt(dec, key)
}

func (m LoginShard) Derive(dec enc.Decoder, cred auth.Credential, pub secret.PublicShard) (ret secret.Secret, err error) {
	priv, err := m.Decrypt(dec, cred)
	if err != nil {
		return
	}

	ret, err = pub.Derive(priv)
	return
}

func (m LoginShard) Update(fn func(*LoginShard)) (ret LoginShard) {
	ret = m
	fn(&ret)
	return
}
