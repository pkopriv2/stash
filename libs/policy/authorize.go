package policy

import (
	"reflect"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// An item is any entity that is managed by a policy
type Item interface {
	GetOrgId() uuid.UUID
	GetPolicyId() uuid.UUID
}

type key struct {
	orgId, policyId uuid.UUID
}

func (a key) GetOrgId() uuid.UUID {
	return a.orgId
}

func (a key) GetPolicyId() uuid.UUID {
	return a.policyId
}

func New(orgId, policyId uuid.UUID) Item {
	return key{orgId, policyId}
}

func Addr(orgId, policyId uuid.UUID) Item {
	return key{orgId, policyId}
}

// Returns a slice of secured objects
func SliceOf(val interface{}) (ret []Item) {
	ref := reflect.ValueOf(val)
	if ref.Kind() != reflect.Slice {
		panic("Expected slice")
	}

	ret = []Item{}
	for i := 0; i < ref.Len(); i++ {
		ret = append(ret, ref.Index(i).Interface().(Item))
	}
	return
}

// Returns the enabled actions for the batch of secured items.
// Requires a consistent org id for the entire batch.
func CollectActions(db Storage, userId uuid.UUID, all ...Item) (ret map[uuid.UUID]Actions, err error) {
	ret = make(map[uuid.UUID]Actions)
	if len(all) == 0 {
		return
	}

	orgId := all[0].GetOrgId()

	var policyIds []uuid.UUID
	for _, cur := range all {
		if cur.GetOrgId() != orgId {
			err = errors.Wrap(errs.ArgError, "Inconsistent ids")
			return
		}
		policyIds = append(policyIds, cur.GetPolicyId())
	}

	ret, err = db.LoadEnabledActions(orgId, userId, dedup(policyIds)...)
	return
}

func dedup(ids []uuid.UUID) (ret []uuid.UUID) {
	tmp := make(map[uuid.UUID]struct{})
	for _, id := range ids {
		tmp[id] = struct{}{}
	}
	for id, _ := range tmp {
		ret = append(ret, id)
	}
	return
}

// Validates that the user has the appopriate actions for an object.
func EnsurePolicyActions(db Storage, orgId, userId, policyId uuid.UUID, actions ...Action) (err error) {
	enabled, err := db.LoadEnabledActions(orgId, userId, policyId)
	if err != nil {
		return
	}

	act, ok := enabled[policyId]
	if !ok {
		err = errors.Wrapf(auth.ErrUnauthorized, "Actions not authorized [%v]", actions)
		return
	}

	for _, a := range actions {
		if !act.Enabled(a) {
			err = errors.Wrapf(auth.ErrUnauthorized, "Action not authorized [%v]", a)
			return
		}
	}
	return
}

type Authorizer func(Actions) error

func (a Authorizer) And(auths ...Authorizer) Authorizer {
	return func(act Actions) (err error) {
		auths = append([]Authorizer{a}, auths...)
		for _, fn := range auths {
			if err = fn(act); err != nil {
				return
			}
		}
		return
	}
}

func (a Authorizer) Or(auths ...Authorizer) Authorizer {
	return func(act Actions) (err error) {
		auths = append([]Authorizer{a}, auths...)
		for _, fn := range auths {
			if err = fn(act); err == nil {
				return
			}
		}
		return
	}
}

var HasAny = Has

func Any() Authorizer {
	return func(a Actions) (err error) {
		if len(a) == 0 {
			err = errors.Wrapf(auth.ErrUnauthorized, "Expected at least one action enabled.")
		}
		return
	}
}

func Has(all ...Action) Authorizer {
	return func(a Actions) (err error) {
		if a.Enabled(Sudo) {
			return
		}

		for _, cur := range all {
			if a.Enabled(cur) {
				return
			}
		}

		err = errors.Wrapf(auth.ErrUnauthorized, "Your actions %v do not include %v", a.Flatten(), all)
		return
	}
}

func Assert(cond bool, msg string, args ...interface{}) Authorizer {
	return func(a Actions) (err error) {
		if !cond {
			err = errors.Wrapf(auth.ErrUnauthorized, msg, args...)
		}
		return
	}
}

func Authorize(db Storage, userId uuid.UUID, fn Authorizer, items ...Item) (err error) {
	enabled, err := CollectActions(db, userId, items...)
	if err != nil {
		return
	}

	for _, act := range enabled {
		if act.Enabled(Sudo) {
			return
		}
		if err = fn(act); err != nil {
			return
		}
	}
	return
}
