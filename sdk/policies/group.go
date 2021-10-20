package policies

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	GroupType = group{}
)

func init() {
	StaticItemTypes.Register(GroupType)
	StaticMemberTypes.Register(GroupType)
}

// Implements the group member type and item type interfaces
type group struct{}

func (u group) Type() policy.Type {
	return policy.GroupType
}

func (u group) GetMemberId(s session.Session, orgId uuid.UUID, name string) (memberId uuid.UUID, err error) {
	group, err := RequireGroupByName(s, orgId, name)
	if err != nil {
		return
	}

	memberId = group.Id
	return
}

func (u group) GetPublicKey(s session.Session, orgId, memberId uuid.UUID) (pub crypto.PublicKey, err error) {
	group, err := RequireGroupById(s, orgId, memberId)
	if err != nil {
		return
	}

	policy, err := RequirePolicyById(s, orgId, group.PolicyId)
	if err != nil {
		return
	}

	pub = policy.Key.Pub
	return
}

func (g group) Name() string {
	return policy.GroupType
}

func (g group) AllActions() []ActionInfo {
	return []ActionInfo{
		NewActionInfo(policy.Sudo, "Sudo", "Can perform all actions"),
		NewActionInfo(policy.Edit, "Edit", "Can make changes to a group's information"),
		NewActionInfo(policy.Delete, "Delete", "Can delete a group"),
	}
}

func (g group) DefaultActions() []policy.Action {
	return []policy.Action{}
}

func (g group) ParseAction(action string) (policy.Action, error) {
	return policy.ParseGroupAction(action)
}

func (g group) GetPolicyIdByName(s session.Session, orgId uuid.UUID, name string) (ret uuid.UUID, err error) {
	group, err := RequireGroupByName(s, orgId, name)
	if err != nil {
		return
	}

	ret = group.PolicyId
	return
}

func (g group) GetPolicyIdByUUID(s session.Session, orgId uuid.UUID, itemId uuid.UUID) (ret uuid.UUID, err error) {
	group, err := RequireGroupById(s, orgId, itemId)
	if err != nil {
		return
	}

	ret = group.PolicyId
	return
}

// Creates a new zero-trust group.
//
// Authorization rules:
//
// * Only >= Org#Manager can create groups.
//
func CreateGroup(s session.Session, orgId uuid.UUID, name string, desc string, strength crypto.Strength) (group policy.Group, err error) {
	lock, err := CreatePolicy(s, orgId, strength, policy.Sudo)
	if err != nil {
		return
	}

	group, err = policy.NewGroup(orgId, lock.Id(), name, desc)
	if err != nil {
		return
	}

	err = SaveGroup(s, group)
	return
}

func SaveGroup(s session.Session, group policy.Group) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(group.OrgId))
	if err != nil {
		return
	}

	err = s.Options().Policies().SaveGroup(token, group)
	return
}

func ListGroups(s session.Session, orgId uuid.UUID, filter policy.GroupFilter, opt ...page.PageOption) (ret []policy.GroupInfo, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, err = s.Options().Policies().ListGroups(token, orgId, filter, page.BuildPage(opt...))
	return
}

func RequireGroupById(s session.Session, orgId, groupId uuid.UUID) (ret policy.Group, err error) {
	ret, ok, err := LoadGroupById(s, orgId, groupId)
	if err != nil || !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNoGroup, "No such group [%v]", groupId))
	}
	return
}

func LoadGroupById(s session.Session, orgId, groupId uuid.UUID) (ret policy.Group, found bool, err error) {
	groups, err := ListGroups(s, orgId,
		policy.BuildGroupFilter(policy.WithGroupIds(groupId)), page.Limit(1))
	if err != nil || len(groups) != 1 {
		return
	}

	found, ret = true, groups[0].Group
	return
}

func RequireGroupByName(s session.Session, orgId uuid.UUID, name string) (ret policy.Group, err error) {
	ret, ok, err := LoadGroupByName(s, orgId, name)
	if err != nil || !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNoGroup, "No such group [%v]", name))
	}
	return
}

func LoadGroupByName(s session.Session, orgId uuid.UUID, name string) (ret policy.Group, found bool, err error) {
	groups, err := ListGroups(s, orgId,
		policy.BuildGroupFilter(policy.WithGroupNames(name)), page.Limit(1))
	if err != nil || len(groups) != 1 {
		return
	}

	found, ret = true, groups[0].Group
	return
}
