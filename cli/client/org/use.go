package org

import (
	"fmt"

	"github.com/cott-io/stash/lang/config"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	UseCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "use",
			Usage: "use",
			Info:  "Activate an organization",
			Help: `
Set the default organization being used during sessions.

Examples:

	$ stash org use example.io

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) < 1 {
					err = errors.Wrap(errs.ArgError, "Must provide an organization")
					return
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return
				}
				defer s.Close()

				org, ok, err := orgs.LoadByName(s, cli.Args().Get(0))
				if err != nil {
					return
				}
				if !ok {
					err = errors.Wrapf(errs.StateError, "No such organization [%v]", cli.Args().Get(0))
					return
				}

				_, ok, err = orgs.LoadMember(s, org.Id, s.AccountId())
				if err != nil {
					return
				}
				if !ok {
					err = errors.Wrapf(errs.StateError, "You are not a member of that organization [%v]", cli.Args().Get(0))
					return
				}

				env.Config["stash.session.org"] = org.Id.String()
				if err = config.WriteConfig(env.Config, tool.DefaultConfigFile, 0755); err != nil {
					err = errors.Errorf("Error writing config file [%v]", tool.DefaultConfigFile)
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully set active organization [%v].\n", cli.Args().Get(0))
				return
			},
		})
)
