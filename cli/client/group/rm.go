package group

import (
	"fmt"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	RmCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "rm",
			Usage: "rm <group>",
			Info:  "Delete a group",
			Help: `
Delete a group.

Examples:

	$ stash group rm devs
`,
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) < 1 {
					err = errors.Wrapf(errs.ArgError, "Must provide a group name or reference")
					return
				}

				gn := cli.Args().Get(0)

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				orgId, err := s.Options().RequireOrgId()
				if err != nil {
					return
				}

				group, err := policies.RequireGroupByName(s, orgId, gn)
				if err != nil {
					return
				}

				if err = policies.SaveGroup(s, group.Delete()); err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Group deleted [%v]\n", gn)
				return
			},
		})
)
