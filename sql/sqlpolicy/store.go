package sqlpolicy

import (
	"fmt"

	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
)

var (
	SchemaPolicy = sql.NewSchema("policy", 0).
		WithStruct(policy.Policy{}).
		WithIndices(
			sql.NewUniqueIndex("policy_id", "org_id", "id", "version")).
		Build()
)

var (
	SchemaPolicyMember = sql.NewSchema("policy_member", 0).
		WithStruct(policy.PolicyMember{}).
		WithIndices(
			sql.NewUniqueIndex("policy_member_id", "org_id", "policy_id", "member_id", "version")).
		Build()
)

var (
	SchemaGroup = sql.NewSchema("policy_group", 0).
		WithStruct(policy.Group{}).
		WithIndices(
			sql.NewUniqueIndex("group_id", "org_id", "id", "version")).
		Build()
)

// Used for fetching user actions.
type EnabledActions struct {
	Id      uuid.UUID
	Actions policy.Actions
}

type SqlStore struct {
	db sql.Driver
}

func NewSqlStore(db sql.Driver, schemas sql.SchemaRegistry) (policy.Storage, error) {
	if err := sql.InitSchemas(db, schemas, SchemaPolicy, SchemaPolicyMember, SchemaGroup); err != nil {
		return nil, err
	}
	return &SqlStore{db}, nil
}

func (s *SqlStore) SaveGroup(group policy.Group) (err error) {
	if group.Deleted {
		return s.DeleteGroup(group)
	}

	return s.db.Do(
		sql.ExpectNone(
			selectGroupByName(group.OrgId, group.Name).
				Where(latestGroup("g")).
				Where("g.id != ?", group.Id)).
			ThenExec(SchemaGroup.Insert(group)))
}

func (s *SqlStore) DeleteGroup(group policy.Group) (err error) {
	return s.db.Do(
		DeletePolicyQuery(group.OrgId, group.PolicyId).
			ThenExec(
				sql.DeleteFrom(SchemaGroup.Name).
					Where("g.org_id = ?", group.OrgId).
					Where("g.id = ?", group.Id)))
}

func (s *SqlStore) ListGroups(orgId uuid.UUID, filter policy.GroupFilter, page page.Page) (ret []policy.Group, err error) {
	query := sql.Select(SchemaGroup.Cols().As("g")...).
		From(SchemaGroup.As("g")).
		Where("g.org_id = ?", orgId).
		Where(latestGroup("g")).
		OrderBy("g.name desc")
	if filter.Names != nil {
		query = query.WhereIn("g.name in (%v)", sql.InStrings(*filter.Names...)...)
	}
	if filter.Ids != nil {
		query = query.WhereIn("g.id in (%v)", sql.InUUIDs(*filter.Ids...)...)
	}
	err = s.db.Do(
		sql.QueryPage(
			query,
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) SavePolicy(p policy.Policy, m policy.PolicyMember) (err error) {
	return s.db.Do(
		sql.Exec(
			SchemaPolicy.Insert(p),
			SchemaPolicyMember.Insert(m)))
}

func (s *SqlStore) SavePolicyMember(m policy.PolicyMember) (err error) {
	if m.Deleted {
		return s.DeletePolicyMember(m)
	}

	return s.db.Do(sql.Exec(SchemaPolicyMember.Insert(m)))
}

func (s *SqlStore) PurgePolicyMember(orgId, memberId uuid.UUID) (err error) {
	return s.db.Do(PurgePolicyMemberQuery(orgId, memberId))
}

func (s *SqlStore) DeletePolicyMember(m policy.PolicyMember) (err error) {
	return s.db.Do(DeletePolicyMemberQuery(m.OrgId, m.PolicyId, m.MemberId))
}

func (s *SqlStore) LoadPolicy(orgId, policyId uuid.UUID) (ret policy.Policy, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaPolicy.SelectAs("p").
				Where("p.org_id = ?", orgId).
				Where("p.id = ?", policyId).
				Where(latestPolicy("p")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadPolicyMember(orgId, policyId, memberId uuid.UUID) (ret policy.PolicyMember, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaPolicyMember.SelectAs("m").
				Where("m.org_id = ?", orgId).
				Where("m.policy_id = ?", policyId).
				Where("m.member_id = ?", memberId).
				Where(latestPolicyMember("m")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) ListPolicyMembers(orgId, policyId uuid.UUID, page page.Page) (ret []policy.PolicyMember, err error) {
	err = s.db.Do(
		sql.QueryPage(
			SchemaPolicyMember.SelectAs("m").
				Where("m.org_id = ?", orgId).
				Where("m.policy_id = ?", policyId).
				Where("not m.deleted").
				Where(latestPolicyMember("m")),
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) LoadPolicyLock(orgId, policyId, userId uuid.UUID) (ret policy.PolicyLock, ok bool, err error) {
	ret, ok, err = s.LoadPolicyViaDirect(orgId, policyId, userId)
	if err != nil || ok {
		return
	}
	ret, ok, err = s.LoadPolicyViaProxy1(orgId, policyId, userId)
	return
}

func (s *SqlStore) LoadEnabledActions(orgId, userId uuid.UUID, policyIds ...uuid.UUID) (ret map[uuid.UUID]policy.Actions, err error) {
	var part1 []EnabledActions
	var part2 []EnabledActions
	err = s.db.Do(
		s.QueryEnabledActionsViaDirect(orgId, userId, policyIds, &part1).
			Then(s.QueryEnabledActionsViaProxy1(orgId, userId, policyIds, &part2)))
	if err != nil {
		return
	}

	ret = indexActionsById(append(part1, part2...))
	return
}

func (s *SqlStore) QueryEnabledActionsViaDirect(orgId, userId uuid.UUID, policyIds []uuid.UUID, dst *[]EnabledActions) sql.Atomic {
	return sql.QueryPage(
		sql.Select(
			SchemaPolicyMember.Cols().Only("policy_id", "actions").As("pm")...).
			From(SchemaPolicyMember.As("pm")).
			Where("pm.org_id = ?", orgId).
			Where("pm.member_id = ?", userId).
			WhereIn("pm.policy_id in (%v)", sql.InUUIDs(policyIds...)...).
			Where(latestPolicyMember("pm")).
			Where(`not pm.deleted`),
		sql.Slice(dst, sql.Struct))
}

func (s *SqlStore) QueryEnabledActionsViaProxy1(orgId, userId uuid.UUID, policyIds []uuid.UUID, dst *[]EnabledActions) (ret sql.Atomic) {
	return sql.QueryPage(
		sql.Select(
			SchemaPolicyMember.Cols().Only("policy_id", "actions").As("direct_member")...).
			From(
				SchemaPolicyMember.As("direct_member"),
				SchemaPolicy.As("proxy1"),
				SchemaPolicyMember.As("proxy1_member")).
			Where("proxy1_member.org_id = ?", orgId).
			Where("proxy1_member.member_id = ?", userId).
			Where(latestPolicyMember("proxy1_member")).
			Where("not proxy1_member.deleted").
			Where("proxy1.org_id = proxy1_member.org_id").
			Where("proxy1.id = proxy1_member.policy_id").
			Where(latestPolicy("proxy1")).
			Where("not proxy1.deleted").
			Where("direct_member.org_id = proxy1.org_id").
			Where("direct_member.member_id = proxy1.id").
			WhereIn("direct_member.policy_id in (%v)", sql.InUUIDs(policyIds...)...).
			Where(latestPolicyMember("direct_member")).
			Where("not direct_member.deleted"),
		sql.Slice(dst, sql.Struct))
}

func (s *SqlStore) LoadPolicyViaDirect(orgId, policyId, userId uuid.UUID) (ret policy.PolicyLock, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			sql.Select(
				SchemaPolicy.Cols().As("p").
					Union(SchemaPolicyMember.Cols().As("m"))...).
				From(
					SchemaPolicy.As("p"),
					SchemaPolicyMember.As("m")).
				Where(`m.org_id = ?`, orgId).
				Where(`m.policy_id = ?`, policyId).
				Where(`m.member_id = ?`, userId).
				Where(latestPolicyMember("m")).
				Where(`not m.deleted`).
				Where(`p.org_id = m.org_id`).
				Where(`p.id = m.policy_id`).
				Where(latestPolicy("p")),
			sql.MultiStruct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadPolicyViaProxy1(orgId, policyId, userId uuid.UUID) (ret policy.PolicyLock, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			sql.Select(
				SchemaPolicy.Cols().As("direct").
					Union(SchemaPolicyMember.Cols().As("direct_member")).
					Union(SchemaPolicy.Cols().As("proxy1")).
					Union(SchemaPolicyMember.Cols().As("proxy1_member"))...).
				From(
					SchemaPolicy.As("direct"),
					SchemaPolicyMember.As("direct_member"),
					SchemaPolicy.As("proxy1"),
					SchemaPolicyMember.As("proxy1_member")).
				Where("proxy1_member.org_id = ?", orgId).
				Where("proxy1_member.member_id = ?", userId).
				Where(latestPolicyMember("proxy1_member")).
				Where("not proxy1_member.deleted").
				Where("proxy1.org_id = proxy1_member.org_id").
				Where("proxy1.id = proxy1_member.policy_id").
				Where(latestPolicy("proxy1")).
				Where("not proxy1.deleted").
				Where("direct_member.org_id = proxy1.org_id").
				Where("direct_member.member_id = proxy1.id").
				Where("direct_member.policy_id = ?", policyId).
				Where(latestPolicyMember("direct_member")).
				Where("not direct_member.deleted").
				Where("direct.org_id = direct_member.org_id").
				Where("direct.id = direct_member.policy_id").
				Where(latestPolicy("direct")).
				Where("not direct.deleted"),
			sql.MultiStruct(&ret),
			&ok))
	return
}

func indexActionsById(actions []EnabledActions) (ret map[uuid.UUID]policy.Actions) {
	ret = make(map[uuid.UUID]policy.Actions)
	for _, a := range actions {
		sum, ok := ret[a.Id]
		if !ok {
			sum = policy.Enable()
		}

		ret[a.Id] = sum.Enable(a.Actions.Flatten()...)
	}
	return
}

func latestPolicy(alias string) string {
	return fmt.Sprintf(`
not exists (
	select
		1
	from
		policy as o
	where
		o.org_id = %v.org_id
		and o.id = %v.id
		and o.version > %v.version
	)`, alias, alias, alias)
}

func latestPolicyMember(alias string) string {
	return fmt.Sprintf(`
not exists (
	select
		1
	from
		policy_member as o
	where
		o.org_id = %v.org_id
		and o.policy_id = %v.policy_id
		and o.member_id = %v.member_id
		and o.version > %v.version
	)`, alias, alias, alias, alias)
}

func latestGroup(alias string) string {
	return fmt.Sprintf(`
not exists (
	select
		1
	from
		policy_group as o
	where
		o.org_id = %v.org_id
		and o.id = %v.id
		and o.version > %v.version
	)`, alias, alias, alias)
}

func selectGroupByName(orgId uuid.UUID, name string) sql.SelectBuilder {
	return SchemaGroup.SelectAs("g").
		Where("g.org_id = ?", orgId).
		Where("g.name = ?", name)
}

func selectGroupById(orgId, groupId uuid.UUID) sql.SelectBuilder {
	return SchemaGroup.SelectAs("g").
		Where("g.org_id = ?", orgId).
		Where("g.id = ?", groupId)
}

func DeletePolicyQuery(orgId, policyId uuid.UUID) sql.Atomic {
	return sql.Exec(
		sql.DeleteFrom(SchemaPolicy.Name).
			Where("org_id = ?", orgId).
			Where("id = ?", policyId),
		sql.DeleteFrom(SchemaPolicyMember.Name).
			Where("org_id = ?", orgId).
			Where("policy_id = ?", policyId),
		sql.DeleteFrom(SchemaPolicyMember.Name).
			Where("org_id = ?", orgId).
			Where("member_id = ?", policyId))
}

func DeletePolicyMemberQuery(orgId, policyId, memberId uuid.UUID) sql.Atomic {
	return sql.Exec(
		sql.DeleteFrom(SchemaPolicyMember.Name).
			Where("org_id = ?", orgId).
			Where("policy_id = ?", policyId).
			Where("member_id = ?", memberId))
}

func PurgePolicyMemberQuery(orgId, memberId uuid.UUID) sql.Atomic {
	return sql.Exec(
		sql.DeleteFrom(SchemaPolicyMember.Name).
			Where("org_id = ?", orgId).
			Where("member_id = ?", memberId))
}
