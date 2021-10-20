package core

import (
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
)

func LoadGroupNames(db policy.Storage, orgId uuid.UUID, groupIds []uuid.UUID) (ret map[uuid.UUID]string, err error) {
	if len(groupIds) == 0 {
		return
	}

	groups, err := db.ListGroups(orgId,
		policy.BuildGroupFilter(
			policy.WithGroupIds(groupIds...)),
		page.Page{})
	if err != nil {
		return
	}

	ret = make(map[uuid.UUID]string)
	for _, group := range groups {
		ret[group.Id] = group.Name
	}
	return
}
