package accounts

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	LookupDisplay      = account.LookupDisplay
	LookupDisplays     = account.LookupDisplays
	LookupPrimaryEmail = account.LookupPrimaryEmail
	LookupPrimaryPhone = account.LookupPrimaryPhone
)

// Adds an identity to an account.  If the identity can be self verified,
// an optional proof may be sent along with the request.  If not, then the appropriate
// messaging protocol will be used to deliver a verification code.
func AddIdentity(s session.Session, id auth.Identity, opts ...auth.IdentityOption) (err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}
	err = s.Options().Accounts().IdentityRegister(token, s.AccountId(), id, auth.BuildIdentityOptions(opts...))
	return
}

// Deletes an identity from the owner's account.
func DeleteIdentity(s session.Session, id auth.Identity) (err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}
	err = s.Options().Accounts().IdentityDelete(token, id)
	return
}

// Verifies an identity on the owner's account.
func IdentityVerify(s session.Session, id auth.Identity, login auth.Login) (err error) {
	creds, err := auth.ExtractCreds(login)
	if err != nil {
		return
	}
	defer creds.Destroy()

	attmpt, err := creds.Auth(crypto.Rand)
	if err != nil {
		return
	}

	err = s.Options().Accounts().IdentityVerify(id, attmpt)
	return
}

// Performs a simple identity lookup.
func LoadIdentity(s session.Session, id auth.Identity) (ret account.Identity, found bool, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}
	ret, found, err = s.Options().Accounts().LoadIdentity(token, id)
	return
}

// Performs a simple identity lookup.  Returns an error if the identity can't be found.
func RequireIdentity(s session.Session, id auth.Identity) (ret account.Identity, err error) {
	ret, ok, err := LoadIdentity(s, id)
	if err != nil || !ok {
		err = errs.Or(err, errors.Wrapf(account.ErrNoIdentity, "No such identity [%v]", id))
	}
	return
}

// Ensures that an identity hasn't already been claimed.
func RequireIdentityUnverified(s session.Session, id auth.Identity) (err error) {
	ret, _, err := LoadIdentity(s, id)
	if err != nil || ret.Verified {
		err = errs.Or(err, errors.Wrapf(account.ErrIdentityRegistered, "Identity already claimed [%v]", id))
	}
	return
}

// Returns the complete list of identities for a given account.
func ListIdentities(s session.Session, opts ...page.PageOption) (ret []account.Identity, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	ret, err = s.Options().Accounts().ListIdentitiesByAccountId(token, s.AccountId(), page.BuildPage(opts...))
	return
}

// Returns the complete list of identities for a given account.
func ListIdentitiesByAccountIds(s session.Session, ids []uuid.UUID) (ret map[uuid.UUID][]account.Identity, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	ret, err = s.Options().Accounts().ListIdentitiesByAccountIds(token, ids)
	return
}
