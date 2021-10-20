package policy

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func ParseGroupAction(str string) (ret Action, err error) {
	switch strings.ToLower(strings.TrimSpace(str)) {
	default:
		err = errors.Wrapf(ErrNotAnAction, "Invalid action [%v]", str)
	case string(Sudo):
		ret = Sudo
	case string(Edit):
		ret = Edit
	case string(Delete):
		ret = Delete
	}
	return
}

type GroupInfo struct {
	Group   `json:"group"`
	Actions Actions `json:"actions"`
}

// Joins the tags on to the collection of blobs.
func DecorateGroups(db Storage, userId uuid.UUID, groups ...Group) (ret []GroupInfo, err error) {
	if len(groups) == 0 {
		return
	}

	var policyIds []uuid.UUID
	for _, g := range groups {
		policyIds = append(policyIds, g.PolicyId)
	}

	actions, err := db.LoadEnabledActions(groups[0].OrgId, userId, policyIds...)
	if err != nil {
		return
	}

	for _, g := range groups {
		ret = append(ret, GroupInfo{Group: g, Actions: actions[g.PolicyId]})
	}
	return
}

// A group is a simple, intermediate data structure that enables
// sets of users and agents
//
// Groups must maintain at least one user at all times.
type Group struct {
	OrgId       uuid.UUID `json:"org_id"`
	PolicyId    uuid.UUID `json:"policy_id"`
	Id          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	Version     int       `json:"version"`
	Deleted     bool      `json:"deleted"`
}

func NewGroup(orgId, policyId uuid.UUID, name, desc string) (group Group, err error) {
	now := time.Now().UTC()

	group = Group{
		PolicyId:    policyId,
		OrgId:       orgId,
		Id:          uuid.NewV4(),
		Name:        name,
		Description: desc,
		Created:     now,
		Updated:     now,
	}
	return
}

func (g Group) GetOrgId() uuid.UUID {
	return g.OrgId
}

func (g Group) GetPolicyId() uuid.UUID {
	return g.PolicyId
}

func (g Group) SetCreated(t time.Time) (ret Group) {
	ret = g
	ret.Created = t.UTC()
	return
}

func (g Group) SetUpdated(t time.Time) (ret Group) {
	ret = g
	ret.Updated = t.UTC()
	return
}

func (g Group) Update(fn func(*Group)) (ret Group) {
	ret = g
	fn(&ret)
	ret.Updated = time.Now().UTC()
	ret.Version = g.Version + 1
	return
}

func (g Group) Delete() (ret Group) {
	return g.Update(func(g *Group) {
		g.Deleted = true
	})
}
