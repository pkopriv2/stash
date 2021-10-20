package policy

import (
	"strings"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type GroupFilter struct {
	Like  *string      `json:"match"`
	Names *[]string    `json:"names"`
	Ids   *[]uuid.UUID `json:"ids"`
}

func ParseGroupFilters(args ...string) (fns []func(*GroupFilter), err error) {
	for _, arg := range args {
		filter, err := ParseGroupFilter(arg)
		if err != nil {
			return nil, err
		}
		fns = append(fns, filter)
	}
	return
}

func ParseGroupFilter(filter string) (fn func(*GroupFilter), err error) {
	if filter == "" {
		fn = func(*GroupFilter) {}
		return
	}

	parts := strings.Split(filter, ":")
	if len(parts) == 1 {
		fn = WithGroupMatch(parts[0])
		return
	}

	switch parts[0] {
	default:
		err = errors.Wrapf(errs.ArgError, "Bad format [%v]. Expected <filter_val>:<val>", filter)
	case "name", "n":
		fn = WithGroupNames(parts[1])
	case "uuid", "id":
		id, err := uuid.FromString(parts[1])
		if err != nil {
			return nil, err
		}

		fn = WithGroupIds(id)
	}
	return
}

func BuildGroupFilter(fns ...func(*GroupFilter)) (ret GroupFilter) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func WithGroupIds(ids ...uuid.UUID) func(*GroupFilter) {
	return func(f *GroupFilter) {
		if f.Ids == nil {
			f.Ids = &[]uuid.UUID{}
		}

		*f.Ids = append(*f.Ids, ids...)
	}
}

func WithGroupNames(names ...string) func(*GroupFilter) {
	return func(f *GroupFilter) {
		if f.Names == nil {
			f.Names = &[]string{}
		}

		*f.Names = append(*f.Names, names...)
	}
}

func WithGroupMatch(like string) func(*GroupFilter) {
	return func(f *GroupFilter) {
		f.Like = &like
	}
}

type Transport interface {

	// Save a group
	SaveGroup(auth.SignedToken, Group) error

	// List/search groups
	ListGroups(t auth.SignedToken, orgId uuid.UUID, filter GroupFilter, page page.Page) ([]GroupInfo, error)

	// Saves a policy and the first member
	CreatePolicy(auth.SignedToken, Policy, PolicyMember) error

	// Saves a policy member
	SavePolicyMember(auth.SignedToken, PolicyMember) error

	// Load a policy
	LoadPolicy(t auth.SignedToken, orgId, policyId uuid.UUID) (Policy, bool, error)

	// Load a policy membership
	LoadPolicyMember(t auth.SignedToken, orgId, policyId, memberId uuid.UUID) (PolicyMember, bool, error)

	// Loads the policy members
	ListPolicyMembers(t auth.SignedToken, orgId, policyId uuid.UUID, page page.Page) ([]PolicyMemberInfo, error)

	// Loads the policy lock for the given user.
	LoadPolicyLock(t auth.SignedToken, orgId, policyId, memberId uuid.UUID) (PolicyLock, bool, error)
}
