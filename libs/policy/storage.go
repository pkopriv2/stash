package policy

import (
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Storage interface {

	// Saves a group and the first member
	SaveGroup(Group) error

	// Search for groups
	ListGroups(orgId uuid.UUID, filter GroupFilter, page page.Page) ([]Group, error)

	// Saves a policy and the first member
	SavePolicy(Policy, PolicyMember) error

	// Saves a policy member
	SavePolicyMember(PolicyMember) error

	// Purge a policy member from the system.  Cannot be undone.
	PurgePolicyMember(orgId, memberId uuid.UUID) error

	// Load a policy roster.  Must have the policy.view.roster
	LoadPolicy(orgId, policyId uuid.UUID) (Policy, bool, error)

	// Load a policy roster.  Must have the policy.view.roster
	LoadPolicyMember(orgId, policyId, userId uuid.UUID) (PolicyMember, bool, error)

	// Load a policy roster.
	ListPolicyMembers(orgId, policyId uuid.UUID, page page.Page) ([]PolicyMember, error)

	// Loads the lists of the enabled actions for all the given policies in the context
	// of the user's permissions.  The returned actions are indexed by their corresponding
	// policy ids.
	LoadEnabledActions(orgId, userId uuid.UUID, policyIds ...uuid.UUID) (map[uuid.UUID]Actions, error)

	// Loads the policy lock for the given user
	LoadPolicyLock(orgId, policyId, userId uuid.UUID) (PolicyLock, bool, error)
}
