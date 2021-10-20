package accounts

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// Loads an account's public key.
func LoadPublicKey(s session.Session, acctId uuid.UUID) (ret crypto.PublicKey, ok bool, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}
	ret, ok, err = s.Options().Accounts().LoadPublicKey(token, acctId)
	return
}

// Loads an account's public key.  Returns an error if one cannot be found
func RequirePublicKey(s session.Session, acctId uuid.UUID) (ret crypto.PublicKey, err error) {
	ret, ok, err := LoadPublicKey(s, acctId)
	if err != nil || !ok {
		err = errs.Or(err, errors.Wrapf(account.ErrNoAccount, "No such account [%v]", acctId))
	}
	return
}
