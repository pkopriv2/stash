package member

import (
	"strings"
	"time"

	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/sdk/accounts"
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
			Info:  "List your organization's members",
			Help: `
List the active members in the organization.

Example:

	$ stash member ls

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				members, err := orgs.ListMembersByOrgId(s, s.Options().OrgId)
				if err != nil {
					return
				}

				ids, err := accounts.ListIdentitiesByAccountIds(s, orgs.CollectMemberIds(members))
				if err != nil {
					return
				}

				template := accountLsTemplate
				if cli.Bool(tool.VFlag.Name) {
					template = accountLsVTemplate
				}

				return displayMembers(env, template, toMemberships(members, accounts.LookupDisplays(ids)))
			},
		})
)

type membership struct {
	Identity auth.Identity
	Issued   time.Time
	Role     auth.Role
}

var (
	accountLsTemplate = `
Memberships(Total={{.Num}}):

      {{ "#/role" | col 8 | header }} {{ "#/identity" | header }}

{{- range .Members}}
    {{"*" | item }} {{ .Role.String | col 8 }} {{ .Identity | id }}
{{- end}}
`

	accountLsVTemplate = `
Memberships(Total={{.Num}}):
{{range .Members}}
{{"*" | item }} {{.Identity | id }}
    Role:   {{.Role }}
    Issued: {{.Issued | date}} ({{.Issued | since}})
{{end}}
`
)

type Sort func(a, b interface{}) int

func nameSort(a, b interface{}) int {
	mA, mB := a.(membership), b.(membership)
	if mA.Identity.Proto == mB.Identity.Proto {
		return strings.Compare(mA.Identity.Val, mB.Identity.Val)
	}
	return strings.Compare(mA.Identity.Proto.String(), mB.Identity.Proto.String())
}

func toMemberships(members []org.Member, identsByAcccountIds map[uuid.UUID]account.Identity) (ret []membership) {
	data := treeset.NewWith(utils.Comparator(nameSort))
	for _, m := range members {
		data.Add(membership{
			Identity: identsByAcccountIds[m.AccountId].Id,
			Issued:   m.Created,
			Role:     m.Role,
		})
	}

	ret = make([]membership, 0, data.Size())
	for _, m := range data.Values() {
		ret = append(ret, m.(membership))
	}
	return
}

func identityFormatter(id auth.Identity) string {
	return auth.FormatFriendlyIdentity(id)
}

func displayMembers(env tool.Environment, template string, mems []membership) error {
	return tool.DisplayStdOut(env, template,
		tool.WithFunc("id", identityFormatter),
		tool.WithData(struct {
			Num     int
			Members []membership
		}{
			len(mems),
			mems,
		}))
}
