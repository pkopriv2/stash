package secret

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	ErrNoFilter = errors.New("Secret:NoFilter")
)

type Filter struct {
	Prefix  *string      `json:"prefix,omitempty"`
	Like    *string      `json:"like,omitempty"`
	Type    *string      `json:"type,omitempty"`
	Names   *[]string    `json:"names,omitempty"`
	Ids     *[]uuid.UUID `json:"ids,omitempty"`
	Tags    *[]string    `json:"tags,omitempty"`
	Deleted *bool        `json:"deleted,omitempty"`
	Hidden  *bool        `json:"hidden,omitempty"`
}

func BuildFilter(fns ...func(*Filter)) (ret Filter) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func ParseFilters(filters []string) (ret []func(*Filter), err error) {
	for _, f := range filters {
		fn, err := ParseFilter(f)
		if err != nil {
			return ret, err
		}

		ret = append(ret, fn)
	}
	return
}

func ParseFilter(filter string) (fn func(*Filter), err error) {
	if filter == "" {
		fn = func(*Filter) {}
		return
	}

	parts := strings.Split(filter, ":")
	if len(parts) == 1 {
		fn = FilterByPrefix(parts[0])
		return
	}

	switch parts[0] {
	default:
		err = errors.Wrapf(ErrNoFilter, "Bad format [%v]. Expected <filter_val>:<val>", filter)
	case "name":
		fn = FilterByName(parts[1])
	case "id":
		id, err := uuid.FromString(parts[1])
		if err != nil {
			return nil, errors.Wrapf(ErrNoFilter, "Bad uuid format [%v]", parts[1])
		}

		fn = FilterByIds(id)
	case "del":
		del, err := strconv.ParseBool(parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "Bad format [%v]", parts[1])
		}

		fn = FilterShowDeleted(del)
	case "hidden":
		dot, err := strconv.ParseBool(parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "Bad format [%v]", parts[1])
		}

		fn = FilterShowHidden(dot)
	}
	return
}

func FilterByIds(ids ...uuid.UUID) func(*Filter) {
	return func(f *Filter) {
		if f.Ids == nil {
			f.Ids = &[]uuid.UUID{}
		}

		*f.Ids = append(*f.Ids, ids...)
	}
}

func FilterByName(name string) func(*Filter) {
	return func(f *Filter) {
		if f.Names == nil {
			f.Names = &[]string{}
		}

		*f.Names = append(*f.Names, name)
	}
}

func FilterByMatch(match string) func(*Filter) {
	return func(f *Filter) {
		f.Like = &match
	}
}

func FilterByPrefix(prefix string) func(*Filter) {
	return func(f *Filter) {
		f.Prefix = &prefix
	}
}

func FilterShowDeleted(t bool) func(*Filter) {
	return func(f *Filter) {
		f.Deleted = &t
	}
}

func FilterShowHidden(t bool) func(*Filter) {
	return func(f *Filter) {
		f.Hidden = &t
	}
}
