package project

import (
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type Storage interface {

	// Saves or updates a project entry
	SaveProject(Project) error

	// Loads a version of a project entry by name.
	LoadPojectByName(orgId uuid.UUID, name string) (Project, bool, error)

	// Loads a version of a project entry by id.
	LoadProjectById(orgId, projectId uuid.UUID, version int) (project, bool, error)

	// Searches the org's secret secrets
	ListProjects(orgId uuid.UUID, filter Filter, page page.Page) ([]Secret, error)

	// Lists all the versions for a given secret
	ListSecretVersions(orgId, secretId uuid.UUID, page page.Page) ([]Secret, error)

	// Saves the blocks for a given secret stream
	SaveBlocks(...Block) error

	// Load the blocks for a given stream
	LoadBlocks(orgId uuid.UUID, streamId uuid.UUID, page page.Page) ([]Block, error)
}
