package identity

import (
	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/session"
	"github.com/urfave/cli"
)

var (
	LsCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "ls",
			Usage: "ls",
			Info:  "List the identities of your account",
			Help: `
Lists all the currently registered identities of the account.

If no identity is specified, the session account is assumed.

Examples:

List the identities of your account:

	$ stash identity ls

`,
			Flags: client.AuthFlags.
				Add(tool.VFlag).
				Add(tool.PageFlags...),
			Exec: IdentityLs,
		})
)

// ** RAW COMMANDS ** //

func IdentityLs(env tool.Environment, c *cli.Context) (err error) {
	session, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer session.Close()

	ids, err := accounts.ListIdentities(session,
		page.Offset(uint64(c.Uint(tool.PageBegFlag.Name))),
		page.Limit(uint64(c.Uint(tool.PageMaxFlag.Name))))
	if err != nil {
		return
	}

	template := identityLsTemplate
	if c.Bool(tool.VFlag.Name) {
		template = identityLsVTemplate
	}

	return DisplayIds(env, template, ids, session.LoginId())
}

var (
	identityLsTemplate = `
Ids(Total={{.Num}}):

        {{ "#/status" | col 12 | header }} {{ "#/identity" | header }}

{{- range .Ids}}
    {{"*" | item }} {{statusSymbol .Verified | mark }} {{status .Verified | col 12 }} {{.Id | id }} {{if eq .Id.String $.Active.String }}{{ "(active)" | info }}{{ end }}
{{- end}}
`

	identityLsVTemplate = `
Ids(Total={{.Num}}):
{{range .Ids}}
{{"*" | header }} {{.Id | id}} {{if eq .Id.String $.Active.String }}{{ "(active)" | info }}{{ end }}
    Protocol: {{.Id.Proto }}
    Verified: {{.Verified }} ({{.Verified | bool | mark}})
    Created:  {{.Created | date}} ({{.Created | since}})
{{end}}
`
)

func Status(verified bool) string {
	if verified {
		return "Verified"
	} else {
		return "Unverified"
	}
}

func StatusSymbol(verified bool) string {
	if verified {
		return tool.OkMark
	} else {
		return tool.InfoMark
	}
}

func DisplayIds(env tool.Environment, template string, ids []account.Identity, active auth.Identity) error {
	return tool.DisplayStdOut(env, template,
		tool.WithFunc("id", auth.FormatFriendlyIdentity),
		tool.WithFunc("status", Status),
		tool.WithFunc("statusSymbol", StatusSymbol),
		tool.WithData(struct {
			Ok     string
			Info   string
			Error  string
			Num    int
			Ids    []account.Identity
			Active auth.Identity
		}{
			tool.OkMark,
			tool.InfoMark,
			tool.ErrorMark,
			len(ids),
			ids,
			active,
		}))
}
