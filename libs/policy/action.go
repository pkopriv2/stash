package policy

import (
	"encoding/json"

	"github.com/pkg/errors"
)

var (
	ErrNotAnAction = errors.New("Policy:NotAnAction")
)

func Enable(all ...Action) (ret Actions) {
	ret = NewEmptyActions()
	for _, a := range all {
		ret[a] = true
	}
	return
}

func ToStrings(all []Action) (ret []string) {
	for _, a := range all {
		ret = append(ret, string(a))
	}
	return
}

func FromStrings(all ...string) (ret []Action) {
	for _, a := range all {
		ret = append(ret, Action(a))
	}
	return
}

// An action is a possible interaction with a resource. Every
// resource will dictate its own actions, with a few globally
// defined actions
type Action string

const (

	// The sudo action gives "root" level privileges to an asset
	Sudo Action = "sudo"

	// The view action allows members to view an asset's data
	View Action = "view"

	// The edit action allows members to manage an asset's state
	Edit Action = "edit"

	// The share action allows members to manage a policy's roster
	Delete Action = "delete"
)

type Actions map[Action]bool

func NewEmptyActions() Actions {
	return make(map[Action]bool)
}

func Unflatten(all []Action) (ret Actions) {
	ret = NewEmptyActions().Enable(all...)
	return
}

func (a Actions) MarshalBinary() (ret []byte, err error) {
	return json.Marshal(a.Flatten())
}

func (a *Actions) UnmarshalBinary(raw []byte) (err error) {
	var all []Action
	if err = json.Unmarshal(raw, &all); err != nil {
		return
	}

	*a = NewEmptyActions()
	for _, act := range all {
		(*a)[act] = true
	}
	return
}

func (a Actions) Copy() (ret Actions) {
	ret = make(map[Action]bool)
	for k, v := range a {
		ret[k] = v
	}
	return
}

func (a Actions) Flatten() (ret []Action) {
	if a[Sudo] {
		return []Action{Sudo}
	}

	ret = make([]Action, 0, len(a))
	for act, v := range a {
		if v {
			ret = append(ret, act)
		}
	}
	return
}

func (a Actions) Enable(all ...Action) (ret Actions) {
	ret = a.Copy()
	for _, act := range all {
		ret[act] = true
	}
	return
}

func (a Actions) Authorize(fn Authorizer) (err error) {
	err = fn(a)
	return
}

func (a Actions) Disable(all ...Action) (ret Actions) {
	ret = a.Copy()
	for _, act := range all {
		ret[act] = false
	}
	return
}

func (a Actions) Enabled(act Action) (ok bool) {
	_, ok = a[act]
	return
}

func (a Actions) Equals(o Actions) (ok bool) {
	if len(a) != len(o) {
		return
	}

	for k, v := range a {
		if o[k] != v {
			return
		}
	}
	ok = true
	return
}
