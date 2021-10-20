package orgs

import (
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/sdk/session"
	uuid "github.com/satori/go.uuid"
)

func CollectMemberIds(members []org.Member) (ret []uuid.UUID) {
	ret = make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		ret = append(ret, m.AccountId)
	}
	return
}

func CollectOrgIds(members []org.Member) (ret []uuid.UUID) {
	ret = make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		ret = append(ret, m.OrgId)
	}
	return
}

func ListMemberships(s session.Session, opts ...page.PageOption) (ret []org.Member, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	ret, err = s.Options().Orgs().ListMembersByAccountId(
		token, s.AccountId(), page.BuildPage(opts...))
	return
}

func ListMembersByOrgId(s session.Session, orgId uuid.UUID, opts ...page.PageOption) (ret []org.Member, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, err = s.Options().Orgs().ListMembersByOrgId(
		token, orgId, page.BuildPage(opts...))
	return
}

func LoadMember(s session.Session, orgId, acctId uuid.UUID) (ret org.Member, ok bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, ok, err = s.Options().Orgs().LoadMember(token, orgId, acctId)
	return
}

func CreateMember(s session.Session, orgId, acctId uuid.UUID, role auth.Role) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	err = s.Options().Orgs().CreateMember(token, orgId, acctId, role)
	return
}

func DeleteMember(s session.Session, orgId, acctId uuid.UUID) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	err = s.Options().Orgs().DeleteMember(token, orgId, acctId)
	return
}

func UpdateMember(s session.Session, orgId, acctId uuid.UUID, role auth.Role) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	err = s.Options().Orgs().UpdateMember(token, orgId, acctId, role)
	return
}
