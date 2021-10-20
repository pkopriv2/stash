package org

import (
	"time"

	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

func MemberDelete(m *Member) {
	m.Deleted = true
}

func MemberUpdateRole(role auth.Role) func(*Member) {
	return func(m *Member) {
		m.Role = role
	}
}

type Member struct {
	Id        uuid.UUID `json:"id"`
	OrgId     uuid.UUID `json:"org_id"`
	AccountId uuid.UUID `json:"account_id"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Deleted   bool      `json:"deleted"`
	Version   int       `json:"version"`
	Role      auth.Role `json:"role"`
}

func NewMember(orgId, acctId uuid.UUID, role auth.Role) Member {
	now := time.Now().UTC()
	return Member{
		Id:        uuid.NewV1(),
		OrgId:     orgId,
		AccountId: acctId,
		Created:   now,
		Updated:   now,
		Role:      role,
	}
}

func (a Member) Update(fn func(*Member)) (ret Member) {
	ret = a
	fn(&ret)
	ret.Version = a.Version + 1
	ret.Updated = time.Now().UTC()
	return
}
