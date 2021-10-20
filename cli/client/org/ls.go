package org

import (
	"strings"
	"time"

	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/emirpasic/gods/utils"
	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
)

var (
	LsCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "ls",
			Usage: "ls",
			Info:  "List your organizations",
			Help: `
List the orgs to which you have active memberships.

Example:

	$ stash org ls

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				members, err := orgs.ListMemberships(s)
				if err != nil {
					return err
				}

				orgns, err := orgs.ListByIds(s, orgs.CollectOrgIds(members))
				if err != nil {
					return err
				}

				template := accountLsTemplate
				if cli.Bool(tool.VFlag.Name) {
					template = accountLsVTemplate
				}

				return displayMembers(env, template, s.Options().OrgId, toMemberships(members, indexById(orgns)))
			},
		})
)

type membership struct {
	Org    string
	OrgId  uuid.UUID
	Issued time.Time
	Role   auth.Role
}

var (
	accountLsTemplate = `
Orgs(Total={{.Num}}):

      {{ "#/role" | col 8 | header }} {{ "#/org" | header }}

{{- range .Members}}
    {{"*" | item }} {{ .Role.String | col 8 }} {{.Org | org}} {{if eq .OrgId.String $.Active.String }}{{ "(active)" | info }}{{ end }}
{{- end}}
`

	accountLsVTemplate = `
Memberships(Total={{.Num}}):
{{range .Members}}
{{"*" | item }} {{.Org }} {{if eq .OrgId.String $.Active.String }}{{ "(active)" | info }}{{ end }}
    Id:     {{.OrgId}}
    Role:   {{.Role }}
    Issued: {{.Issued | date}} ({{.Issued | since}})
{{end}}
`
)

type Sort func(a, b interface{}) int

func nameSort(a, b interface{}) int {
	mA, mB := a.(membership), b.(membership)
	return strings.Compare(mA.Org, mB.Org)
}

func indexById(orgs []org.Org) (ret map[uuid.UUID]org.Org) {
	ret = make(map[uuid.UUID]org.Org)
	for _, o := range orgs {
		ret[o.Id] = o
	}
	return
}

func toMemberships(members []org.Member, orgsById map[uuid.UUID]org.Org) (ret []membership) {
	data := treeset.NewWith(utils.Comparator(nameSort))
	for _, m := range members {
		data.Add(membership{
			Org:    orgsById[m.OrgId].Name,
			OrgId:  m.OrgId,
			Issued: m.Created,
			Role:   m.Role,
		})
	}

	ret = make([]membership, 0, data.Size())
	for _, m := range data.Values() {
		ret = append(ret, m.(membership))
	}
	return
}

func displayMembers(env tool.Environment, template string, active uuid.UUID, mems []membership) error {
	return tool.DisplayStdOut(env, template,
		tool.WithData(struct {
			Active  uuid.UUID
			Num     int
			Members []membership
		}{
			active,
			len(mems),
			mems,
		}))
}
