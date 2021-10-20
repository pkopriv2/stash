package policies

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// An action info documents in human-readable terms
// the definition of a particular action.
type ActionInfo struct {
	Action policy.Action `json:"action"`
	Name   string        `json:"name"`
	Desc   string        `json:"desc"`
}

func NewActionInfo(a policy.Action, name string, desc string) ActionInfo {
	return ActionInfo{a, name, desc}
}

// An item type specifies a class of objects that all share
// the same policy configuration and lookup methods
type ItemType interface {

	// Returns the canonical name of this type.  Must be unique
	Name() string

	// Returns a list of supported actions.
	AllActions() []ActionInfo

	// Parses an action from user input
	ParseAction(string) (policy.Action, error)

	// Returns the default actions when sharing with no options
	DefaultActions() []policy.Action

	// Locates the policy id for an item of this type
	// using a simple human-readable name of the item
	GetPolicyIdByName(s session.Session, orgId uuid.UUID, name string) (uuid.UUID, error)

	// Locates the policy id for an item of this type
	// using the canonical uuid of the item
	GetPolicyIdByUUID(s session.Session, orgId, itemId uuid.UUID) (uuid.UUID, error)
}

var (
	StaticItemTypes = TypeRegistry{
		&sync.RWMutex{},
		make(map[string]ItemType)}
)

type TypeRegistry struct {
	lock    *sync.RWMutex
	byProto map[string]ItemType
}

func (t *TypeRegistry) Register(info ItemType) {
	t.lock.Lock()
	defer t.lock.Unlock()
	name := strings.ToLower(info.Name())
	if name == "" {
		panic("Invalid type. Must have a non-zero name")
	}

	t.byProto[name] = info
}

func (t TypeRegistry) LookupByProtocol(proto string) (ret ItemType, ok bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	ret, ok = t.byProto[strings.ToLower(proto)]
	return
}

// An item ref is a reference to a policy item.  The reference
// may either be in uuid or human-readable form.
type ItemRef struct {
	Type ItemType
	id   *uuid.UUID
	name *string
}

func newItemRef(t ItemType, raw string) ItemRef {
	if id, err := uuid.FromString(raw); err == nil {
		return ItemRef{Type: t, id: &id}
	} else {
		return ItemRef{Type: t, name: &raw}
	}
}

func (r ItemRef) ToMember() (MemberRef, error) {
	return ParseMemberRef(r.String())
}

func (r ItemRef) String() string {
	if r.id != nil {
		return fmt.Sprintf("%v://%v", r.Type.Name(), r.id.String())
	} else {
		return fmt.Sprintf("%v://%v", r.Type.Name(), *r.name)
	}
}

func (r ItemRef) ParseAction(action string) (policy.Action, error) {
	if action == string(policy.Sudo) {
		return policy.Sudo, nil
	} else {
		return r.Type.ParseAction(action)
	}
}

func (r ItemRef) GetPolicyId(s session.Session, orgId uuid.UUID) (uuid.UUID, error) {
	if r.id != nil {
		return r.Type.GetPolicyIdByUUID(s, orgId, *r.id)
	} else {
		return r.Type.GetPolicyIdByName(s, orgId, *r.name)
	}
}

func ParseItemRef(uri string) (ret ItemRef, err error) {
	ptr := ref.Pointer(uri)

	t, ok := StaticItemTypes.LookupByProtocol(ptr.Protocol())
	if !ok {
		err = errors.Wrapf(errs.ArgError, "Unknown type for [%v]", uri)
		return
	}

	ret = newItemRef(t, ptr.Document())
	return
}

func LoadPolicyId(s session.Session, orgId uuid.UUID, raw string) (policyId uuid.UUID, err error) {
	ref, err := ParseItemRef(raw)
	if err != nil {
		return
	}

	policyId, err = ref.GetPolicyId(s, orgId)
	return
}
