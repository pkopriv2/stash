package member

import (
	"fmt"

	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	RmCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "rm",
			Usage: "rm <identity>",
			Info:  "Delete a member",
			Help: `
Delete a member from the organization.

Examples:

	$ stash org add @fred --role Manager

`,
			Flags: tool.NewFlags(RoleFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) < 1 {
					err = errors.Wrap(errs.ArgError, "Must provide an identity")
					return
				}

				ident, err := client.LoadIdentity(env, cli.Args().Get(0))
				if err != nil {
					return
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return
				}
				defer s.Close()

				id, found, err := accounts.LoadIdentity(s, ident)
				if err != nil {
					return
				}
				if !found || !id.Verified {
					err = errors.Wrapf(errs.StateError, "No such identity [%v]", cli.Args().Get(0))
					return
				}

				if id.AccountId == s.AccountId() {
					err = errors.Wrap(errs.ArgError, "Cannot update your own membership")
					return
				}

				if err = orgs.DeleteMember(s, s.Options().OrgId, id.AccountId); err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully deleted member [%v]", cli.Args().Get(0))
				return
			},
		})
)
