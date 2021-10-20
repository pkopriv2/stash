package account

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

// Core transport mechanism.
type Transport interface {
	auth.Transport

	// Creates a new account with a secret.  (not to be used in browser based contexts...)
	Register(primary auth.Identity, attmpt auth.Attempt, secret Secret, shard LoginShard, opts auth.IdentityOptions) error

	// Returns the account secret (core + shard(uri))
	LoadSecretAndShard(t auth.SignedToken, id uuid.UUID, uri string, version int) (SecretAndShard, bool, error)

	// Loads an identity.  Only publicly consumable information is returned
	LoadIdentity(t auth.SignedToken, id auth.Identity) (Identity, bool, error)

	// Loads an account's identities
	ListIdentitiesByAccountId(t auth.SignedToken, acctId uuid.UUID, opts page.Page) ([]Identity, error)

	// Loads an account's identities
	ListIdentitiesByAccountIds(t auth.SignedToken, acctIds []uuid.UUID) (map[uuid.UUID][]Identity, error)

	//// Searches account identities.  All identity searches are global.
	//ListPreferredIdentities(ids []uuid.UUID) ([]Identity, error)

	// Registers an identity with the account service.
	IdentityRegister(t auth.SignedToken, acctId uuid.UUID, id auth.Identity, opts auth.IdentityOptions) error

	// Verifies an identity using the given auth attempt.
	IdentityVerify(id auth.Identity, attempt auth.Attempt) error

	// Deletes an identity.  Is now available for use by others.
	IdentityDelete(t auth.SignedToken, id auth.Identity) error

	// Registers the given login with attempt and shard
	LoginRegister(t auth.SignedToken, acctId uuid.UUID, auth auth.Attempt, shard LoginShard) error

	// Deletes the given login.  Must not be the same login uri as the token
	LoginDelete(t auth.SignedToken, acctId uuid.UUID, uri string) error

	// Returns the signing key of the given acct
	LoadPublicKey(t auth.SignedToken, acctId uuid.UUID) (crypto.PublicKey, bool, error)

	//// Returns the account summary of the given acct
	//LoadSettings(t auth.SignedToken, id uuid.UUID) (Settings, bool, error)

	//// Updates the account options (Limited set of updates available)
	//SettingsUpdate(t auth.SignedToken, settings AccountSettings) error
}
