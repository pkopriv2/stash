package auth

import (
	"strings"

	"github.com/cott-io/stash/lang/errs"
	"github.com/pkg/errors"
)

// Authorization roles. (Generally applied to accounts, subscriptions, and trusts)
const (
	None Role = iota
	Member
	Manager
	Director
	Owner
)

type Role int

func (r Role) String() string {
	switch r {
	default:
		return "Unknown"
	case None:
		return "None"
	case Member:
		return "Member"
	case Manager:
		return "Manager"
	case Director:
		return "Director"
	case Owner:
		return "Owner"
	}
}

func (r Role) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *Role) UnmarshalText(text []byte) (err error) {
	*r, err = ParseRole(string(text))
	return
}

func ParseRole(str string) (Role, error) {
	switch strings.ToLower(str) {
	default:
		return None, errors.Wrapf(errs.ArgError, "Invalid role [%v]", str)
	case "none":
		return None, nil
	case "member":
		return Member, nil
	case "manager":
		return Manager, nil
	case "director":
		return Director, nil
	case "owner":
		return Owner, nil
	}
}

func Min(first Role, rest ...Role) Role {
	for _, cur := range rest {
		if cur < first {
			first = cur
		}
	}
	return first
}

func Max(first Role, rest ...Role) Role {
	for _, cur := range rest {
		if cur > first {
			first = cur
		}
	}
	return first
}

func IsValidRole(role Role) bool {
	return role > None && role <= Owner
}
