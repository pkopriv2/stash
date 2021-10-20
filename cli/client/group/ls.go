package group

import (
	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	"github.com/urfave/cli"
)

var (
	LsCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "ls",
			Usage: "ls [<filter>]",
			Info:  "List and search for groups",
			Help:  ``,
			Flags: tool.NewFlags(tool.VFlag).Add(tool.PageFlags...),
			Exec:  GroupLs,
		})
)

func GroupLs(env tool.Environment, cli *cli.Context) (err error) {
	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return err
	}
	defer s.Close()

	var filters []func(*policy.GroupFilter)
	if len(cli.Args()) > 0 {
		filters, err = policy.ParseGroupFilters(cli.Args()...)
		if err != nil {
			return
		}
	}

	orgId, err := s.Options().RequireOrgId()
	if err != nil {
		return
	}

	groups, err := policies.ListGroups(s, orgId, policy.BuildGroupFilter(filters...), tool.ParsePageOpts(cli)...)
	if err != nil {
		return
	}

	template := groupLsTemplate
	if cli.Bool(tool.VFlag.Name) {
		template = groupLsVTemplate
	}

	return tool.DisplayStdOut(env, template,
		tool.WithFunc("actions", client.ActionsFormatter),
		tool.WithData(struct {
			Groups []policy.GroupInfo
		}{
			groups,
		}))
}

var (
	groupLsTemplate = `
Groups(Total={{len .Groups}}):

    {{ "#/name" | col 32 | header }} {{ "#/actions" | header }}

{{- range .Groups}}
  {{"*" | item}} {{ .Name | col 32 }} [{{ .Actions | actions | info }}]
{{- end}}
`

	groupLsVTemplate = `
Groups(Total={{len .Groups}}):
{{range .Groups}}
{{"*" | header}} {{.Name}}
    Created:    {{.Created | date}} ({{.Created | since}})
    Updated:    {{.Updated | date}} ({{.Updated | since}})
    Actions:
{{- range .Actions.Flatten }}
      - {{ . | printf "%v" | info }}
{{- end}}
{{end}}
`
)
