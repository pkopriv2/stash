package core

import (
	"github.com/cott-io/stash/libs/org"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func RequireOrg(db org.Storage, orgId uuid.UUID) (ret org.Org, err error) {
	ret, found, err := db.LoadOrgById(orgId)
	if err != nil {
		return
	}

	if !found || ret.Deleted {
		err = errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId)
	}
	return
}

func RequireOrgMembership(db org.Storage, orgId, acctId uuid.UUID) (ret org.Member, err error) {
	ret, found, err := db.LoadMember(orgId, acctId)
	if err != nil {
		return
	}

	if !found || ret.Deleted {
		err = errors.Wrapf(org.ErrNoMember, "No such membership [%v] to org [%v]", acctId, orgId)
	}
	return
}
