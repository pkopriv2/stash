package sqlsecret

import (
	"fmt"

	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/secret"
	uuid "github.com/satori/go.uuid"
)

var (
	SchemaSecret = sql.NewSchema("secret", 0).
		WithStruct(secret.Secret{}).
		WithIndices(
			sql.NewUniqueIndex("secret_id", "org_id", "id", "version"),
			sql.NewIndex("secret_by_name", "org_id", "name")).
		Build()
)

var (
	SchemaTag = sql.NewSchema("secret_tag", 0).
		WithStruct(Tag{}).
		WithIndices(
			sql.NewUniqueIndex("secret_tag_id", "org_id", "secret_id", "name")).
		Build()
)

var (
	SchemaBlock = sql.NewSchema("secret_block", 0).WithStruct(secret.Block{}).
		WithIndices(
			sql.NewUniqueIndex("secret_block_id", "org_id", "stream_id", "idx")).
		Build()
)

type Tag struct {
	OrgId    uuid.UUID
	SecretId uuid.UUID
	Name     string
}

type SqlStore struct {
	db sql.Driver
}

func NewSqlStore(db sql.Driver, schemas sql.SchemaRegistry) (secret.Storage, error) {
	if err := sql.InitSchemas(db, schemas, SchemaSecret, SchemaBlock, SchemaTag); err != nil {
		return nil, err
	}
	return &SqlStore{db}, nil
}

func (s *SqlStore) SaveSecret(secret secret.Secret) (err error) {
	return s.db.Do(
		sql.ExpectNone(
			selectSecretByName(secret.OrgId, secret.Name).
				Where(latestSecret("b")).
				Where("not b.deleted").
				Where("b.id != ?", secret.Id)).
			ThenExec(SchemaSecret.Insert(secret)).
			Then(
				purgeOldSecretQuery(secret.OrgId, secret.Id)))
}

func (s *SqlStore) LoadSecretByName(orgId uuid.UUID, name string, version int) (ret secret.Secret, ok bool, err error) {
	query := SchemaSecret.SelectAs("b").
		Where(`b.org_id = ?`, orgId).
		Where(`b.name = ?`, name)

	if version < 0 {
		query = query.Where(latestSecret("b"))
	} else {
		query = query.Where("b.version = ?", version)
	}

	err = s.db.Do(sql.QueryOne(query, sql.Struct(&ret), &ok))
	return
}

func (s *SqlStore) LoadSecretById(orgId, secretId uuid.UUID, version int) (ret secret.Secret, ok bool, err error) {
	query := SchemaSecret.SelectAs("b").
		Where(`b.org_id = ?`, orgId).
		Where(`b.id = ?`, secretId)

	if version < 0 {
		query = query.Where(latestSecret("b"))
	} else {
		query = query.Where("b.version = ?", version)
	}

	err = s.db.Do(
		sql.QueryOne(
			query,
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) ListSecrets(orgId uuid.UUID, filter secret.Filter, page page.Page) (ret []secret.Secret, err error) {
	query := sql.Select(SchemaSecret.Cols().As("b")...).
		From(SchemaSecret.As("b")).
		Where("b.org_id = ?", orgId).
		Where(latestSecret("b")).
		OrderBy("b.name")

	if filter.Type != nil {
		query = query.Where("b.type = ?", *filter.Type)
	}
	if filter.Deleted == nil || !*filter.Deleted {
		query = query.Where("not b.deleted")
	}
	if filter.Like != nil {
		query = query.Where("lower(b.name) like ?", "%"+*filter.Like+"%")
	}
	if filter.Prefix != nil {
		query = query.Where("lower(b.name) like ?", *filter.Prefix+"%")
	}
	if filter.Names != nil {
		query = query.WhereIn("lower(b.name) in (%v)", sql.InStrings(*filter.Names...)...)
	}
	if filter.Ids != nil {
		query = query.WhereIn("b.id in (%v)", sql.InUUIDs(*filter.Ids...)...)
	}

	if filter.Hidden == nil || !*filter.Hidden {
		if filter.Ids == nil && filter.Names == nil {
			query = query.Where("lower(b.name) not like ?", ".%")
		}
	}
	if filter.Tags != nil {
		query = query.WhereIn(`exists (
			select
				1
			from
				secret_tag as o
			where
				o.org_id = b.org_id
				and o.secret_id = b.id
				and o.name in (%v)
			)`, sql.InStrings(*filter.Tags...)...)
	}

	err = s.db.Do(
		sql.QueryPage(
			query,
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) ListSecretVersions(orgId, secretId uuid.UUID, page page.Page) (ret []secret.Secret, err error) {
	err = s.db.Do(
		sql.QueryPage(
			sql.Select(SchemaSecret.Cols().As("b")...).
				From(SchemaSecret.As("b")).
				Where(`b.org_id = ?`, orgId).
				Where(`b.id  = ?`, secretId).
				OrderBy("b.version desc"),
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) SaveBlocks(blocks ...secret.Block) error {
	var inserts []sql.Query
	for _, b := range blocks {
		inserts = append(inserts, SchemaBlock.Insert(b))
	}
	return s.db.Do(sql.Exec(inserts...))
}

func (s *SqlStore) AddTag(orgId, secretId uuid.UUID, tags ...string) (err error) {
	inserts := sql.Nothing
	for _, t := range tags {
		inserts = inserts.ThenExec(
			SchemaTag.Insert(Tag{orgId, secretId, t}))
	}

	return s.db.Do(inserts)
}

func (s *SqlStore) DelTag(orgId, secretId uuid.UUID, tags ...string) (err error) {
	return s.db.Do(
		sql.Exec(
			sql.DeleteFrom(SchemaTag.Name).
				Where("org_id = ?", orgId).
				Where("secret_id = ?", secretId).
				WhereIn("name in (%v)", sql.InStrings(tags...)...)))
}

func (s *SqlStore) ListAvailableTags(orgId uuid.UUID, page page.Page) (ret []string, err error) {
	err = s.db.Do(
		sql.QueryPage(
			sql.Select(SchemaTag.Cols().Only("name").As("t")...).
				Distinct().
				From(SchemaTag.As("t")).
				Where("t.org_id = ?", orgId).
				OrderBy("t.name asc"),
			sql.Slice(&ret, sql.Value),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) ListTags(orgId uuid.UUID, secretIds []uuid.UUID) (ret map[uuid.UUID][]string, err error) {
	var tags []Tag
	err = s.db.Do(
		sql.QueryPage(
			sql.Select(SchemaTag.Cols().As("t")...).
				From(SchemaTag.As("t")).
				Where(`t.org_id = ?`, orgId).
				WhereIn(`t.secret_id in (%v)`, sql.InUUIDs(secretIds...)...),
			sql.Slice(&tags, sql.Struct)))
	if err != nil {
		return
	}

	ret = indexTags(tags, bySecretId)
	return
}

func (s *SqlStore) LoadBlocks(orgId, streamId uuid.UUID, page page.Page) (ret []secret.Block, err error) {
	err = s.db.Do(
		sql.QueryPage(
			SchemaBlock.SelectAs("b").
				Where("b.org_id = ?", orgId).
				Where("b.stream_id = ?", streamId).
				OrderBy("b.idx asc"),
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func latestSecret(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				secret as o
			where
				o.org_id = %v.org_id
				and o.id = %v.id
				and o.version > %v.version
		)`, alias, alias, alias)
}

func selectSecretByName(orgId uuid.UUID, name string) sql.SelectBuilder {
	return SchemaSecret.SelectAs("b").
		Where(`b.org_id = ?`, orgId).
		Where(`b.name = ?`, name)
}

func purgeOldSecretQuery(orgId, newId uuid.UUID) sql.Atomic {
	return sql.Exec(
		SchemaBlock.Delete().
			Where(`org_id = ?`, orgId).
			Where(`stream_id in (
				select
					old.stream_id
				from
					secret as new, secret as old
				where
					new.org_id = ?
					and new.id = ?
					and old.org_id = new.org_id
					and old.name = new.name
					and old.id != new.id
				)`, orgId, newId),
		SchemaSecret.Delete().
			Where(`org_id = ?`, orgId).
			Where(`id in (
				select
					old.id
				from
					secret as new, secret as old
				where
					new.org_id = ?
					and new.id = ?
					and old.org_id = new.org_id
					and old.name = new.name
					and old.id != new.id
				)`, orgId, newId),
	)
}

func deleteSecretByName(orgId uuid.UUID, name string) sql.DeleteBuilder {
	return SchemaSecret.Delete().
		Where(`org_id = ?`, orgId).
		Where(`name = ?`, name)
}

func bySecretId(t Tag) uuid.UUID {
	return t.SecretId
}

func indexTags(tags []Tag, indexFn func(Tag) uuid.UUID) (ret map[uuid.UUID][]string) {
	ret = make(map[uuid.UUID][]string)
	for _, t := range tags {
		index := indexFn(t)
		ret[index] = append(ret[index], t.Name)
	}
	return
}
