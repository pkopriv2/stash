package accounts

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
)

// Adds a login to the given account
func AddLogin(s session.Session, login auth.Login) (err error) {
	cred, err := auth.ExtractCreds(login)
	if err != nil {
		return
	}
	defer cred.Destroy()

	attempt, err := cred.Auth(crypto.Rand)
	if err != nil {
		return errors.Wrapf(err, "Error generating auth attempt [%v]", cred.Uri())
	}

	shard, err := s.Secret().NewLoginShard(cred)
	if err != nil {
		return
	}

	token, err := s.FetchToken()
	if err != nil {
		return
	}

	err = s.Options().Accounts().LoginRegister(token, s.AccountId(), attempt, shard)
	return
}

// Removes a login from the account.
func DeleteLogin(s session.Session, uri string) (err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	err = s.Options().Accounts().LoginDelete(token, s.AccountId(), uri)
	return
}
