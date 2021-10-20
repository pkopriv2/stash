package sqlaccount

import (
	"fmt"

	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

var (
	SchemaIdentity = sql.NewSchema("account_identity", 0).
		WithStruct(account.Identity{}).
		WithIndices(
			sql.NewUniqueIndex("account_identity_by_uri", "uri", "version")).
		Build()
)

var (
	SchemaSecret = sql.NewSchema("account_secret", 0).
		WithStruct(account.Secret{}).
		WithIndices(
			sql.NewUniqueIndex("account_secret_by_uri", "account_id", "version")).
		Build()
)

var (
	SchemaLogin = sql.NewSchema("account_login", 0).
		WithStruct(account.Login{}).
		WithIndices(
			sql.NewUniqueIndex("account_login_by_id", "account_id", "uri", "version")).
		Build()
)

var (
	SchemaLoginShard = sql.NewSchema("account_login_shard", 0).
		WithStruct(account.LoginShard{}).
		WithIndices(
			sql.NewUniqueIndex("account_login_shard_by_id", "account_id", "uri", "version")).
		Build()
)

var (
	SchemaSettings = sql.NewSchema("account_settings", 0).
		WithStruct(account.Settings{}).
		WithIndices(
			sql.NewUniqueIndex("account_settings_by_id", "account_id", "version")).
		Build()
)

type SqlStore struct {
	db sql.Driver
}

func NewSqlStore(db sql.Driver, schemas sql.SchemaRegistry) (account.Storage, error) {
	if err := sql.InitSchemas(db, schemas,
		SchemaSecret,
		SchemaIdentity,
		SchemaLogin,
		SchemaLoginShard,
		SchemaSettings,
	); err != nil {
		return nil, err
	}
	return &SqlStore{db}, nil
}

func (s *SqlStore) CreateAccount(id account.Identity, login account.Login, secret account.Secret, shard account.LoginShard, settings account.Settings) (err error) {
	return s.db.Do(
		sql.ExpectNone(
			selectSettingsById(settings.AccountId)).
			ThenExec(SchemaIdentity.Insert(id)).
			ThenExec(SchemaLogin.Insert(login)).
			ThenExec(SchemaSecret.Insert(secret)).
			ThenExec(SchemaLoginShard.Insert(shard)).
			ThenExec(SchemaSettings.Insert(settings)))
}

func (s *SqlStore) LoadIdentity(id auth.Identity) (ret account.Identity, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaIdentity.SelectAs("i").
				Where("i.uri = ?", id.Uri()).
				Where(latestIdentity("i")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadSecret(accountId uuid.UUID) (ret account.Secret, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaSecret.SelectAs("s").
				Where("s.account_id = ?", accountId).
				Where(latestSecret("s")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadLogin(accountId uuid.UUID, uri string) (ret account.Login, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaLogin.SelectAs("l").
				Where("l.account_id = ?", accountId).
				Where("l.uri = ?", uri).
				Where(latestLogin("l")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadLoginShard(accountId uuid.UUID, uri string, version int) (ret account.LoginShard, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaLoginShard.SelectAs("l").
				Where("l.account_id = ?", accountId).
				Where("l.uri = ?", uri).
				Where("l.version = ?", version),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) LoadSettings(accountId uuid.UUID) (ret account.Settings, ok bool, err error) {
	err = s.db.Do(
		sql.QueryOne(
			SchemaSettings.SelectAs("s").
				Where("s.account_id = ?", accountId).
				Where(latestSettings("s")),
			sql.Struct(&ret),
			&ok))
	return
}

func (s *SqlStore) ListIdentities(accountId uuid.UUID, page page.Page) (ret []account.Identity, err error) {
	err = s.db.Do(
		sql.QueryPage(
			SchemaIdentity.SelectAs("i").
				Where("i.account_id = ?", accountId).
				Where(latestIdentity("i")).
				OrderBy("i.uri desc"),
			sql.Slice(&ret, sql.Struct),
			sql.LimitPtr(page.Limit),
			sql.OffsetPtr(page.Offset)))
	return
}

func (s *SqlStore) ListIdentitiesByIds(acctIds []uuid.UUID) (ret []account.Identity, err error) {
	err = s.db.Do(
		sql.QueryPage(
			SchemaIdentity.SelectAs("i").
				WhereIn(`i.account_id in (%v)`, sql.InUUIDs(acctIds...)...).
				Where(latestIdentity("i")),
			sql.Slice(&ret, sql.Struct),
			sql.Limit(uint64(128*len(acctIds)))))
	return
}

func (s *SqlStore) SaveLogin(login account.Login, shard account.LoginShard) (err error) {
	if login.Deleted {
		return s.DeleteLogin(login)
	}
	err = s.db.Do(
		sql.Exec(
			SchemaLogin.Insert(login),
			SchemaLoginShard.Insert(shard)))
	return
}

func (s *SqlStore) DeleteLogin(login account.Login) (err error) {
	err = s.db.Do(
		sql.Exec(
			SchemaLogin.Delete().
				Where("account_id = ?", login.AccountId).
				Where("uri = ?", login.Uri),
			SchemaLoginShard.Delete().
				Where("account_id = ?", login.AccountId).
				Where("uri = ?", login.Uri)))
	return
}

func (s *SqlStore) SaveIdentity(id account.Identity) (err error) {
	if id.Deleted {
		return s.DeleteIdentity(id)
	}
	err = s.db.Do(
		sql.Exec(
			SchemaIdentity.Insert(id)))
	return
}

func (s *SqlStore) DeleteIdentity(id account.Identity) (err error) {
	err = s.db.Do(
		sql.Exec(
			SchemaIdentity.Delete().
				Where("uri = ?", id.Uri)))
	return
}

func (s *SqlStore) SaveSettings(settings account.Settings) (err error) {
	err = s.db.Do(
		sql.Exec(
			SchemaSettings.Insert(settings)))
	return
}

func selectSettingsById(id uuid.UUID) sql.SelectBuilder {
	return SchemaSettings.SelectAs("s").
		Where("s.account_id = ?", id)
}

func latestIdentity(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				account_identity as o
			where
				o.uri = %v.uri
				and o.version > %v.version
		)`, alias, alias)
}

func latestLogin(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				account_login as o
			where
				o.account_id = %v.account_id
				and o.uri = %v.uri
				and o.version > %v.version
		)`, alias, alias, alias)
}

func latestSecret(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				account_secret as o
			where
				o.account_id = %v.account_id
				and o.version > %v.version
		)`, alias, alias)
}

func latestSettings(alias string) string {
	return fmt.Sprintf(`
		not exists (
			select
				1
			from
				account_settings as o
			where
				o.account_id = %v.account_id
				and o.version > %v.version
		)`, alias, alias)
}
