package org

import (
	"errors"
	"regexp"
	"time"

	uuid "github.com/satori/go.uuid"
)

var (
	orgMatch = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9\\-\\_\\.]+[a-zA-Z0-9]$")
)

func IsOrg(str string) bool {
	return orgMatch.MatchString(str)
}

var (
	ErrNoOrg          = errors.New("Org:NoOrg")
	ErrNoUsers        = errors.New("Org:NoUsers")
	ErrNoMember       = errors.New("Org:NoMember")
	ErrNoSubscription = errors.New("Org:NoSubscription")
	ErrOrgExists      = errors.New("Org:Exists")
)

func OrgEnable(d *Org) {
	d.Enabled = true
}

func OrgDisable(d *Org) {
	d.Enabled = false
}

func OrgDelete(d *Org) {
	d.Deleted = true
	d.Enabled = false
}

type Org struct {
	Id      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Version int       `json:"version"`
	Enabled bool      `json:"enabled"`
	Deleted bool      `json:"deleted"`
	Display string    `json:"display"`
	Address string    `json:"address"`
	URL     string    `json:"url"`
}

func NewOrg(name string) Org {
	now := time.Now().UTC()
	return Org{
		Id:      uuid.NewV4(),
		Name:    name,
		Created: now,
		Updated: now,
		Enabled: true,
	}
}

func (o Org) Update(fn func(*Org)) (ret Org) {
	ret = o
	fn(&ret)
	ret.Version = o.Version + 1
	ret.Updated = time.Now().UTC()
	return
}
