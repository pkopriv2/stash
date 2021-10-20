package core

import (
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func RequireLogin(db account.Storage, acctId uuid.UUID, uri string) (ret account.Login, err error) {
	ret, found, err := db.LoadLogin(acctId, uri)
	if err != nil {
		return
	}

	if !found || ret.Deleted {
		err = errors.Wrapf(auth.ErrUnauthorized, "No such login [%v] for account [%v]", uri, acctId)
	}
	return
}

func RequireIdentity(db account.Storage, id auth.Identity) (ret account.Identity, err error) {
	ret, found, err := db.LoadIdentity(id)
	if err != nil {
		return
	}

	if !found || ret.Deleted {
		err = errors.Wrapf(account.ErrNoIdentity, "No such identity [%v]", id)
		return
	}

	if !ret.Verified {
		err = errors.Wrapf(account.ErrIdentityUnverified, "Unverified identity [%v]", id)
	}
	return
}

func LookupDisplays(db account.Storage, acctIds []uuid.UUID) (ret map[uuid.UUID]auth.Identity, err error) {
	ret = make(map[uuid.UUID]auth.Identity)
	for _, acctId := range acctIds {
		ident, err := LookupIdentity(db, acctId)
		if err != nil {
			return nil, err
		}

		ret[ident.AccountId] = ident.Id
	}
	return
}

func LookupIdentity(db account.Storage, acctId uuid.UUID) (ret account.Identity, err error) {
	ids, err := db.ListIdentities(acctId, page.BuildPage(page.Limit(16)))
	if err != nil {
		return
	}

	ret = account.LookupDisplay(ids)
	return
}

func LookupEmail(db account.Storage, acctId uuid.UUID) (ret account.Identity, ok bool, err error) {
	ids, err := db.ListIdentities(acctId, page.BuildPage(page.Limit(16)))
	if err != nil {
		return
	}

	ret, ok = account.LookupPrimaryEmail(ids)
	return
}

func LookupPhone(db account.Storage, acctId uuid.UUID) (ret account.Identity, ok bool, err error) {
	ids, err := db.ListIdentities(acctId, page.BuildPage(page.Limit(16)))
	if err != nil {
		return
	}

	ret, ok = account.LookupPrimaryPhone(ids)
	return
}
