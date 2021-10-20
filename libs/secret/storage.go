package secret

import (
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Storage interface {

	// Saves or updates a secret entry
	SaveSecret(Secret) error

	// Loads a version of a secret entry by name.  If version < 0, the latest is returned
	LoadSecretByName(orgId uuid.UUID, name string, version int) (Secret, bool, error)

	// Loads a version of a secret entry by id.  If version < 0, the latest is returned
	LoadSecretById(orgId, secretId uuid.UUID, version int) (Secret, bool, error)

	// Searches the org's secret secrets
	ListSecrets(orgId uuid.UUID, filter Filter, page page.Page) ([]Secret, error)

	// Lists all the versions for a given secret
	ListSecretVersions(orgId, secretId uuid.UUID, page page.Page) ([]Secret, error)

	// Saves the blocks for a given secret stream
	SaveBlocks(...Block) error

	// Load the blocks for a given stream
	LoadBlocks(orgId uuid.UUID, streamId uuid.UUID, page page.Page) ([]Block, error)
}
