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
	RmCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "rm",
			Usage: "rm <secret>",
			Info:  "Delete a secret",
			Help: `
Deletes a secret.  The secret is recoverable as long
as no *new* secret with the same name is created.
			`,
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) != 1 {
					err = errors.Wrapf(errs.ArgError, "Must provide a secret")
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

				updated, err := secret.Update().SetDeleted(true).Compile()
				if err != nil {
					return
				}
				if err = secrets.SaveSecret(s, updated); err != nil {
					return
				}

				_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "Successfully deleted [%v]\n", cli.Args().Get(0))
				return
			},
		})
)
