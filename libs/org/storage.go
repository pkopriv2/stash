package org

import (
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Filter struct {
	Like      *string      `json:"like,omitempty"`
	Name      *string      `json:"names,omitempty"`
	OrgId     *uuid.UUID   `json:"org_id,omitempty"`
	OrgIds    *[]uuid.UUID `json:"org_ids,omitempty"`
	AccountId *uuid.UUID   `json:"account_id,omitempty"`
}

func BuildFilter(fns ...func(*Filter)) (ret Filter) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func FilterByName(name string) func(*Filter) {
	return func(f *Filter) {
		f.Name = &name
	}
}

func FilterByOrgId(id uuid.UUID) func(*Filter) {
	return func(f *Filter) {
		f.OrgId = &id
	}
}

func FilterByAccountId(id uuid.UUID) func(*Filter) {
	return func(f *Filter) {
		f.AccountId = &id
	}
}

func FilterByOrgIds(ids ...uuid.UUID) func(*Filter) {
	return func(f *Filter) {
		if f.OrgIds == nil {
			f.OrgIds = &[]uuid.UUID{}
		}

		*f.OrgIds = append(*f.OrgIds, ids...)
	}
}

type Storage interface {

	// Stores the org ( and the owner's membership )
	CreateOrg(Org, Subscription, Member) error

	// Updates the org
	SaveOrg(Org) error

	// Lists orgs
	ListOrgs(Filter, page.Page) ([]Org, error)

	// Load an org by its identifier
	LoadOrgById(uuid.UUID) (Org, bool, error)

	// Saves a subscription
	SaveSubscription(Subscription) error

	// Loads the subscription
	LoadSubscription(orgId uuid.UUID) (Subscription, bool, error)

	// Saves the org membership.
	SaveMember(Member) error

	// Loads the membership
	LoadMember(orgId, acctId uuid.UUID) (Member, bool, error)

	// Lists the memberships
	ListMembers(Filter, page.Page) ([]Member, error)

	//// Returns a breakdown of the active memberships.
	//ActiveMemberCount(uuid.UUID) (num int, err error)
}
