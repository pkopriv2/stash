package group

import (
	"fmt"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	StrengthFlag = tool.StringFlag{
		Name:    "strength",
		Usage:   "Define the security requirements of your group (Weak,Moderate,Strong,Maximum)",
		Default: crypto.Moderate.String(),
	}

	CreateCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "create",
			Usage: "create <group>",
			Info:  "Create a new group",
			Help: `
Creates a new group.  Groups may be members of policies and
can be used as an effective strategy of managing large
organizations.

Examples:

Create a new group with *Strong* security:

	$ stash group create devs --strength Strong
`,
			Flags: tool.NewFlags(StrengthFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) < 1 {
					err = errors.Wrapf(errs.ArgError, "Must provide a group name or reference")
					return
				}

				name, desc := cli.Args().Get(0), cli.Args().Get(1)

				strength, err := crypto.ParseStrength(cli.String(StrengthFlag.Name))
				if err != nil {
					return
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				orgId, err := s.Options().RequireOrgId()
				if err != nil {
					return
				}

				group, err := policies.CreateGroup(s, orgId, name, desc, strength)
				if err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "\nYou have successfully created a group [%v]!\n", group.Name)
				return
			},
		})
)
