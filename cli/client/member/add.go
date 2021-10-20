package member

import (
	"fmt"

	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	RoleFlag = tool.StringFlag{
		Name:    "role",
		Usage:   "The role of the member (Owner, Director, Manager, Member)",
		Default: "Member",
	}

	AddCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "add",
			Usage: "add <identity> [--role <role>]",
			Info:  "Add a member",
			Help: `
Add a member to the organization.  Every member must have an accompanying
role.  The role must be one of:

* Owner    - Can do anything
* Director - Can elect managers
* Manager  - Can elect members
* Member   - Can act within an organization

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

				role, err := auth.ParseRole(cli.String(RoleFlag.Name))
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
					err = errors.Wrap(errs.StateError, "Cannot update your own membership")
					return
				}

				_, found, err = orgs.LoadMember(s, s.Options().OrgId, id.AccountId)
				if err != nil {
					return
				}

				if found {
					if err = orgs.UpdateMember(s, s.Options().OrgId, id.AccountId, role); err != nil {
						return
					}
				} else {
					if err = orgs.CreateMember(s, s.Options().OrgId, id.AccountId, role); err != nil {
						return
					}
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully added member [%v] with role [%v]", cli.Args().Get(0), role)
				return
			},
		})
)
