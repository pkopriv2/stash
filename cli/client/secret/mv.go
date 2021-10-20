package secret

import (
	"fmt"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	MvCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "mv",
			Usage: "mv <src> <dst>",
			Info:  "Rename a secret",
			Help:  ``,
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) != 2 {
					err = errors.Wrapf(errs.ArgError, "Must provide a source and destination")
					return
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				secret, err := secrets.RequireByName(s, s.Options().OrgId, cli.Args().Get(0))
				if err != nil {
					return
				}

				updated, err := secret.Update().SetName(cli.Args().Get(1)).Compile()
				if err != nil {
					return
				}

				if err = secrets.SaveSecret(s, updated); err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully renamed [%v] to [%v]",
					cli.Args().Get(0), cli.Args().Get(1))
				return
			},
		})
)
