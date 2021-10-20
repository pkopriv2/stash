package sqlorg

import (
	"fmt"
	"strings"

	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

var (
	SchemaOrg = sql.NewSchema("org", 0).
		WithStruct(org.Org{}).
		WithIndices(
			sql.NewUniqueIndex("org_by_id", "id", "version"),
			sql.NewIndex("org_by_name", "name", "version")).
		Build()
)

var (
	SchemaMember = sql.NewSchema("member", 0).
		WithStruct(org.Member{}).
		WithIndices(
			sql.NewUniqueIndex("member_by_org_id", "org_id", "account_id", "version"),
			sql.NewIndex("member_by_account_id", "org_id", "account_id", "version")).
		Build()
)

var (
	SchemaSubscription = sql.NewSchema("subscription", 0).
		WithStruct(org.Subscription{}).
		WithIndices(
			sql.NewUniqueIndex("sub_by_id", "org_id", "version")).
		Build()
)

type SqlStore struct {
	db sql.Driver
}

func NewSqlStore(db sql.Driver, schemas sql.SchemaRegistry) (org.Storage, error) {
	if err := sql.InitSchemas(db, schemas,
		SchemaOrg,
		SchemaMember,
		SchemaSubscription,
	); err != nil {
		return nil, err
	}
	return &SqlStore{db}, nil
}

func (s *SqlStore) CreateOrg(org org.Org, sub org.Subscription, member org.Member) (err error) {
	err = s.db.Do(
		sql.ExpectNone(
			selectOrgByName(org.Name)).
			Then(sql.ExpectNone(
				selectOrgById(org.Id))).
			ThenExec(SchemaOrg.Insert(org)).
			ThenExec(SchemaSubscription.Insert(sub)).
			ThenExec(SchemaMember.Insert(member)))
	return
}

func (s *SqlStore) SaveOrg(org org.Org) (err error) {
	if org.Deleted {
		err = s.DeleteOrg(org)
		return
	}

	err = s.db.Do(
		sql.ExpectNone(
			selectOrgByName(org.Name).
				Where(latestOrg("o")).
				Where("o.id != ?", org.Id)).
			ThenExec(SchemaOrg.Insert(org)))
	return
}

func (s *SqlStore) DeleteOrg(org org.Org) (err error) {
	err = s.db.Do(
		sql.Exec(
			SchemaOrg.Delete().
				Where("id = ?", org.Id),
			SchemaMember.Delete().
				Where("org_id = ?", org.Id),
			SchemaSubscription.Delete().
				Where("org_id = ?", org.Id)))
	return
}

func (s *SqlStore) ListOrgs(filter org.Filter, page page.Page) (ret []org.Org, err error) {
	query := SchemaOrg.SelectAs("o").
		Where(latestOrg("o"))
	if filter.OrgId != nil {
		query = query.Where("o.id = ?", *filter.OrgId)
	}
	if filter.Name != nil {
		query = query.Where("lower(o.name) = ?", strings.ToLower(*filter.Name))
	}
	if filter.OrgIds != nil {
		query = query.WhereIn("o.id in (%v)", sql.InUUIDs(*filter.OrgIds...)...)
	}

	err = s.db.Do(
		sql.QueryPage(query,
			sql.Slice(&ret, sql.Struct),
			sql.OffsetPtr(page.Offset),
			sql.LimitPtr(page.Limit)))
	return
}

func (s *SqlStore) LoadOrgById(id uuid.UUID) (ret org.Org, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaOrg.SelectAs("o").
				Where("o.id = ?", id).
				Where(latestOrg("o")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) SaveSubscription(sub org.Subscription) (err error) {
	err = s.db.Do(sql.Exec(SchemaSubscription.Insert(sub)))
	return
}

func (s *SqlStore) LoadSubscription(orgId uuid.UUID) (ret org.Subscription, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaSubscription.SelectAs("s").
				Where("s.org_id = ?", orgId).
				Where(latestSubscription("s")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) SaveMember(m org.Member) (err error) {
	if m.Deleted {
		return s.DeleteMember(m)
	}

	err = s.db.Do(sql.Exec(SchemaMember.Insert(m)))
	return
}

func (s *SqlStore) DeleteMember(m org.Member) (err error) {
	err = s.db.Do(
		sql.Exec(
			SchemaMember.Delete().
				Where("org_id = ?", m.OrgId).
				Where("account_id = ?", m.AccountId)))
	return
}

func (s *SqlStore) LoadMember(orgId, acctId uuid.UUID) (ret org.Member, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaMember.SelectAs("m").
				Where("m.org_id = ?", orgId).
				Where("m.account_id = ?", acctId).
				Where(latestMember("m")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) ListMembers(filter org.Filter, page page.Page) (ret []org.Member, err error) {
	query := SchemaMember.SelectAs("m").
		Where(latestMember("m"))
	if filter.OrgId != nil {
		query = query.Where("m.org_id = ?", *filter.OrgId)
	}
	if filter.AccountId != nil {
		query = query.Where("m.account_id = ?", *filter.AccountId)
	}

	err = s.db.Do(
		sql.QueryPage(query,
			sql.Slice(&ret, sql.Struct),
			sql.OffsetPtr(page.Offset),
			sql.LimitPtr(page.Limit)))
	return
}

func selectOrgByName(name string) sql.SelectBuilder {
	return SchemaOrg.SelectAs("o").Where("lower(o.name) = ?", strings.ToLower(name))
}

func selectOrgById(id uuid.UUID) sql.SelectBuilder {
	return SchemaOrg.SelectAs("o").Where("o.id = ?", id)
}

func latestOrg(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				org as other
			where
				other.id = %v.id
				and other.version > %v.version
		)`, alias, alias)
}

func latestMember(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				member as o
			where
				o.org_id = %v.org_id
				and o.account_id = %v.account_id
				and o.version > %v.version
		)`, alias, alias, alias)
}

func latestSubscription(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				subscription as o
			where
				o.org_id = %v.org_id
				and o.version > %v.version
		)`, alias, alias)
}
