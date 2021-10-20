package secrets

import (
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	uuid "github.com/satori/go.uuid"
)

var (
	SecretType = secretItem{}
)

func init() {
	policies.StaticItemTypes.Register(secretItem{})
}

type secretItem struct{}

func (p secretItem) Name() string {
	return "secret"
}

func (p secretItem) AllActions() []policies.ActionInfo {
	return []policies.ActionInfo{
		policies.NewActionInfo(policy.Sudo, "Sudo", "Can perform all actions"),
		policies.NewActionInfo(policy.View, "View Contents", "Can view the contents of the secret"),
		policies.NewActionInfo(policy.Edit, "Edit Contents", "Can view & edit the contents of the secret"),
		policies.NewActionInfo(policy.Delete, "Delete", "Can delete the secret.  *Caution*"),
		policies.NewActionInfo(secret.Restore, "Restore Versions", "Can view history and restore past versions"),
	}
}

func (p secretItem) DefaultActions() []policy.Action {
	return []policy.Action{policy.View}
}

func (p secretItem) ParseAction(str string) (policy.Action, error) {
	return secret.ParseAction(str)
}

func (p secretItem) GetPolicyIdByName(s session.Session, orgId uuid.UUID, name string) (id uuid.UUID, err error) {
	secret, err := RequireByName(s, orgId, name)
	if err != nil {
		return
	}

	id = secret.PolicyId
	return
}

func (p secretItem) GetPolicyIdByUUID(s session.Session, orgId uuid.UUID, itemId uuid.UUID) (id uuid.UUID, err error) {
	secret, err := RequireById(s, orgId, itemId)
	if err != nil {
		return
	}

	id = secret.PolicyId
	return
}
