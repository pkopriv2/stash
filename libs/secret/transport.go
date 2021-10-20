package secret

import (
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	ErrCorrupt = errors.New("Secret:Corrupt")
)

type Transport interface {

	// Saves a secret.  The secret may be at any version.  A conflict
	// will be thrown if a concurrent update takes place.
	SaveSecret(auth.SignedToken, Secret) error

	// Searches the secrets for an organization using the provided filter.
	ListSecrets(token auth.SignedToken, orgId uuid.UUID, filter Filter, page page.Page) ([]SecretSummary, error)

	// Loads a secret using its unique id.
	ListSecretVersions(token auth.SignedToken, orgId, secretId uuid.UUID, page page.Page) ([]Secret, error)

	// Loads a secret using its unique id.
	LoadSecret(token auth.SignedToken, orgId, secretId uuid.UUID, version int) (Secret, bool, error)

	// Saves a page of blocks.
	SaveBlocks(token auth.SignedToken, blocks ...Block) error

	// Loads a page of blocks for the given secret.  If the version is set to -1, then the latest is returned.
	LoadBlocks(token auth.SignedToken, orgId, secretId uuid.UUID, version int, page page.Page) ([]Block, error)
}
