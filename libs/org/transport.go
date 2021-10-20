package org

import (
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Transport interface {

	// Returns the billing key
	LoadBillingKey(t auth.SignedToken) (string, error)

	// Creates a new org.
	Purchase(t auth.SignedToken, name string, plan Purchase) (Org, error)

	// Lists orgs by ids
	ListOrgsByIds(t auth.SignedToken, ids []uuid.UUID) ([]Org, error)

	// Loads an org by its unique identifier
	LoadOrgById(t auth.SignedToken, id uuid.UUID) (Org, bool, error)

	// Loads an org by its unique identifier
	LoadOrgByName(t auth.SignedToken, name string) (Org, bool, error)

	// Updates the org (Limited set of updates available)
	SaveOrg(t auth.SignedToken, org Org) error

	// Creates a new member
	CreateMember(t auth.SignedToken, orgId, acctId uuid.UUID, role auth.Role) error

	// Update a member's role
	UpdateMember(t auth.SignedToken, orgId, acctId uuid.UUID, role auth.Role) error

	// Deletes a member
	DeleteMember(t auth.SignedToken, orgId, acctId uuid.UUID) error

	// Loads a membership for a given account and org.
	LoadMember(t auth.SignedToken, orgId, acctId uuid.UUID) (Member, bool, error)

	// Lists the memberships for an account
	ListMembersByAccountId(t auth.SignedToken, acctId uuid.UUID, opts page.Page) ([]Member, error)

	// Lists the memberships for an organization
	ListMembersByOrgId(t auth.SignedToken, acctId uuid.UUID, opts page.Page) ([]Member, error)

	// Loads a particular subscription
	LoadSubscription(t auth.SignedToken, orgId uuid.UUID) (SubscriptionSummary, bool, error)

	// Lists the subscriptions of an account
	UpdateSubscription(t auth.SignedToken, orgId uuid.UUID, purchase Purchase) error

	// Lists the subscriptions of an account
	DeleteSubscription(t auth.SignedToken, orgId uuid.UUID) error

	// Lists the subscriptions of an account
	ListInvoices(t auth.SignedToken, orgId uuid.UUID, opts page.Page) ([]billing.Invoice, error)
}
