package account

import (
	"io"
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

func LoginDelete(m *Login) error {
	m.Deleted = true
	return nil
}

func LoginReset(rand io.Reader, enc enc.Encoder, attmpt auth.Attempt) func(*Login) error {
	return func(cur *Login) (err error) {
		a, err := auth.NewAuthenticator(rand, attmpt)
		if err != nil {
			return
		}

		cur.Auth, err = auth.EncodeAuth(enc, a)
		cur.Uri = attmpt.Uri()
		cur.Type = a.Type()
		cur.Deleted = false
		return
	}
}

// An account auth is a server-side only component that adds durability to an authenticator
type Login struct {
	AccountId uuid.UUID
	Type      string
	Uri       string
	Deleted   bool
	Version   int
	Auth      []byte
	Created   time.Time
	Updated   time.Time
}

func NewLogin(enc enc.Encoder, acctId uuid.UUID, attmpt auth.Attempt) (ret Login, err error) {
	a, err := auth.NewAuthenticator(crypto.Rand, attmpt)
	if err != nil {
		return
	}

	raw, err := auth.EncodeAuth(enc, a)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	ret = Login{acctId, attmpt.Type(), attmpt.Uri(), false, 0, raw, now, now}
	return
}

func (m Login) Extract(dec enc.Decoder) (ret auth.Authenticator, err error) {
	return auth.DecodeAuth(dec, m.Auth)
}

func (m Login) Validate(dec enc.Decoder, attmpt auth.Attempt) error {
	raw, err := m.Extract(dec)
	if err != nil {
		return err
	}
	return raw.Validate(attmpt)
}

func (a Login) Update(fn func(*Login) error) (ret Login, err error) {
	ret = a
	err = fn(&ret)
	ret.Version = a.Version + 1
	ret.Updated = time.Now().UTC()
	return
}
