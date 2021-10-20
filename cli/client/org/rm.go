package org

import (
	"fmt"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/term"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	RmCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "rm",
			Usage: "rm",
			Info:  "Delete your organization",
			Help: `

Examples:

	$ stash org rm

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return
				}
				defer s.Close()

				org, ok, err := orgs.LoadById(s, s.Options().OrgId)
				if err != nil {
					return
				}
				if !ok {
					err = errors.Wrapf(errs.StateError, "No such organization [%v]", s.Options().OrgId)
					return
				}

				if err = DisplayCancelPlan(env, org.Name); err != nil {
					return
				}

				err = term.ReadPrompt(
					term.NewPrompt(
						fmt.Sprintf("Please type '%v' to confirm", org.Name),
						term.WithAutoRetry(),
						term.WithAutoCheck(
							term.Equals(org.Name))),
					env.Terminal.IO,
					term.SetNone)
				if err != nil {
					err = errors.Wrapf(err, "Aborted")
					return
				}

				member, ok, err := orgs.LoadMember(s, org.Id, s.AccountId())
				if err != nil {
					return
				}
				if !ok {
					err = errors.Wrapf(errs.StateError, "You are not a member of the organization")
					return
				}
				if member.Role < auth.Owner {
					err = errors.Wrapf(errs.StateError, "Only owners may delete organizations")
					return
				}

				if err = orgs.Cancel(s, org.Id); err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully deleted organization [%v].\n", org.Name)
				return
			},
		})
)

func DisplayCancelPlan(env tool.Environment, on string) error {
	return tool.DisplayStdOut(env, cancelPlanTemplate,
		tool.WithData(struct {
			Org string
		}{
			on,
		}))
}

var (
	cancelPlanTemplate = `
{{ "# Cancel" | header }}

This will cancel your subscription to {{.Org}}.  All future invoices
will be canceled.

{{ "# Notice" | header }}

Once your subscription has been canceled, your organization will be
available for purchase by others!

{{ "# Thank You" | header }}

We are sorry to see you go, but we really appreciate your business.

Thanks,

{{ "-The Stash Team" | info }}

`
)
