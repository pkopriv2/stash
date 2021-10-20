package secret

import (
	"strings"

	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
)

var (
	HiddenFlag = tool.BoolFlag{
		Name:  "a",
		Usage: "Include hidden secrets"}

	LsCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "ls",
			Usage: "ls [/<prefix>]",
			Info:  "List and search for secrets",
			Help:  ``,
			Flags: tool.NewFlags(tool.VFlag, HiddenFlag).Add(tool.PageFlags...),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				var filters []func(*secret.Filter)
				if len(cli.Args()) > 0 {
					filters, err = secret.ParseFilters(cli.Args())
					if err != nil {
						return
					}
				}

				if cli.Bool(HiddenFlag.Name) {
					filters = append(filters, secret.FilterShowHidden(true))
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				if len(cli.Args()) == 1 {
					sec, ok, err := secrets.LoadByName(s, s.Options().OrgId, cli.Args().Get(0))
					if err != nil {
						return err
					}

					if ok {
						revs, err := secrets.ListVersions(s, sec.OrgId, sec.Id, tool.ParsePageOpts(cli)...)
						if err != nil {
							return err
						}

						authors, err := secrets.CollectAuthors(s, secret.ToSecretSummaries(revs))
						if err != nil {
							return err
						}

						return tool.DisplayStdOut(env, secretRevsTemplate,
							tool.WithFunc("id", auth.FormatFriendlyIdentity),
							tool.WithData(struct {
								Secrets []secret.Secret
								Authors map[uuid.UUID]auth.Identity
							}{
								revs,
								authors,
							}))
					}
				}

				results, err := secrets.Search(s, s.Options().OrgId,
					secret.BuildFilter(filters...),
					tool.ParsePageOpts(cli)...)
				if err != nil {
					return
				}

				authors, err := secrets.CollectAuthors(s, results)
				if err != nil {
					return
				}

				template := secretLsTemplate
				if cli.Bool(tool.VFlag.Name) {
					template = secretLsVTemplate
				}

				return tool.DisplayStdOut(env, template,
					tool.WithFunc("actions", actionsFormatter),
					tool.WithFunc("id", auth.FormatFriendlyIdentity),
					tool.WithData(struct {
						Secrets []secret.SecretSummary
						Authors map[uuid.UUID]auth.Identity
					}{
						results,
						authors,
					}))
			},
		})
)

var (
	secretLsTemplate = `
Secrets(Total={{len .Secrets}}):

      {{ "#/name" | col 48 | header }} {{ "#/actions" | header }}

{{- range .Secrets}}
    {{"*" | item}} {{- if .Deleted }} {{ .Name | col 40 }} {{ "deleted" | notice }} {{ else }} {{ .Name | col 48 }} {{ end -}} [{{ .Actions | actions | info }}]
{{- end}}
`

	secretLsVTemplate = `
Secrets(Total={{len .Secrets}}):

{{- range .Secrets}}

{{"*" | item}} {{ .Name }} {{- if .Deleted }} [{{ "deleted" | notice }}] {{ end }}
    Description:  {{ .Description }}
    Revision:     {{ .Version }}
    Blocks:       {{ .StreamSize }}
    Created:      {{ .Created | date }}
    Updated:      {{ .Updated | date }}
    Author:       {{ index $.Authors .AuthorId | id }}
    Comment:      {{ .Comment }}
    Signature:    {{ .AuthorSig.Data | bin }}
    Signing Key   {{ .AuthorSig.Key }}
    Signing Hash: {{ .AuthorSig.Hash }}

{{- end}}
`
)

var (
	secretRevsTemplate = `
Secrets(Total={{len .Secrets}}):

      {{ "#/rev" | col 8 | header }} {{ "#/author" | col 32 | header }} {{ "#/name" | header }}

{{- range .Secrets}}
    {{"*" | item}} {{ .Version | printf "%v" | col 8 }} {{ index $.Authors .AuthorId | id | col 32 }} {{ .Name }}
{{- end}}
`
)

func actionsFormatter(a policy.Actions) string {
	if len(a) == 0 {
		return "unauthorized"
	}
	if a.Enabled("sudo") {
		return "sudo"
	}
	return strings.Join(policy.ToStrings(a.Flatten()), ",")
}
