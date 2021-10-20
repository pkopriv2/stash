package account

import (
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Storage interface {

	// Stores the core account components.
	CreateAccount(Identity, Login, Secret, LoginShard, Settings) error

	// Loads the account profile
	LoadIdentity(auth.Identity) (Identity, bool, error)

	// Loads the account profile
	ListIdentities(acctId uuid.UUID, page page.Page) ([]Identity, error)

	// Loads the account profile
	ListIdentitiesByIds(acctIds []uuid.UUID) ([]Identity, error)

	// Loads the account secret
	LoadSecret(acctId uuid.UUID) (Secret, bool, error)

	// Loads an account authenticator by id and authentication uri.
	LoadLogin(acctId uuid.UUID, uri string) (Login, bool, error)

	// Loads an account shard by id and authentication uri.
	LoadLoginShard(acctId uuid.UUID, uri string, version int) (LoginShard, bool, error)

	// Loads the account settings
	LoadSettings(acctId uuid.UUID) (Settings, bool, error)

	// Stores the account login shard. These are always updated in tandem
	SaveLogin(auth Login, shard LoginShard) error

	// Saves an identity.  Either add or update
	SaveIdentity(Identity) error

	// Update account settings
	SaveSettings(Settings) error
}
