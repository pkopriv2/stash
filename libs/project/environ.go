package project

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

type Environ struct {
	Id       uuid.UUID `json:"id"`
	OrgId    uuid.UUID `json:"org_id"`
	PolicyId uuid.UUID `json:"policy_id"`
	Name     string    `json:"project"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Deleted  bool      `json:"deleted"`
	Version  int       `json:"version"`
}

func NewProject(name string, orgId, policyId uuid.UUID) Project {
	now := time.Now().UTC()
	return Project{
		Id:       uuid.NewV4(),
		OrgId:    orgId,
		PolicyId: policyId,
		Name:     name,
		Created:  now,
		Updated:  now,
	}
}
