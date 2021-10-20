package secret

import (
	"bytes"
	"io"

	"github.com/alecthomas/chroma/quick"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/mime"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	ViewCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "view",
			Usage: "view <secret>",
			Info:  "View a secret",
			Help: `
View a secret.

Example:

	$ stash secret view /project1/dev

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) != 1 {
					err = errors.Wrapf(errs.ArgError, "Expected a secret")
					return
				}

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				sec, err := secrets.RequireByName(s, s.Options().OrgId, cli.Args().Get(0))
				if err != nil {
					return
				}

				if err = policy.Has(policy.View)(sec.Actions); err != nil {
					return
				}

				buf := &bytes.Buffer{}
				if err = secrets.Read(s, sec.Secret, buf); err != nil {
					return
				}

				ptr := ref.Pointer(cli.Args().Get(0))

				var fmt string
				switch ptr.Mime() {
				default:
					_, err = io.Copy(env.Terminal.IO.StdOut(), buf)
					return
				case mime.Json:
					fmt = "json"
				case mime.Yaml:
					fmt = "yaml"
				case mime.Toml:
					fmt = "toml"
				}

				return quick.Highlight(env.Terminal.IO.StdOut(), string(buf.Bytes()), fmt, "terminal256", "solarized-dark")
			},
		})
)
