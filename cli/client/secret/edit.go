package secret

import (
	"bytes"
	"fmt"

	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/mime"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/lang/term"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	EditCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "edit",
			Usage: "edit /<project>/<env>",
			Info:  "Edit a secret",
			Help: `
Edit a secret.

Example:

	$ stash secret edit /myproject/dev

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

				if err = secret.VerifyName(cli.Args().Get(0)); err != nil {
					return
				}

				tmp, ok, err := secrets.LoadByName(s, s.Options().OrgId, cli.Args().Get(0))
				if err != nil {
					return
				}

				var val []byte
				if ok {
					if err = policy.Has(policy.Edit)(tmp.Actions); err != nil {
						return
					}

					buf := &bytes.Buffer{}
					if err = secrets.Read(s, tmp.Secret, buf); err != nil {
						return
					}

					val = buf.Bytes()
				}

				ptr := ref.Pointer(cli.Args().Get(0))

				format := term.Text
				switch ptr.Mime() {
				case mime.Json:
					format = term.Json
				case mime.Yaml:
					format = term.Yaml
				case mime.Toml:
					format = term.Toml
				}

				var next []byte
				if err = term.SystemEditor.Edit(format, val, &next); err != nil {
					return
				}

				if bytes.Equal(val, next) {
					fmt.Fprintf(env.Terminal.IO.StdOut(), "Nothing updated.\n")
					return
				}

				switch ptr.Mime() {
				case mime.Json:
					var dst interface{}
					if err = enc.Json.DecodeBinary(next, &dst); err != nil {
						err = errors.Wrapf(err, "Invalid json [%v]", cli.Args().Get(0))
						return
					}
				case mime.Yaml:
					var dst interface{}
					if err = enc.Yaml.DecodeBinary(next, &dst); err != nil {
						err = errors.Wrapf(err, "Invalid yaml [%v]", cli.Args().Get(0))
						return
					}
				case mime.Toml:
					var dst interface{}
					if err = enc.Toml.DecodeBinary(next, &dst); err != nil {
						err = errors.Wrapf(err, "Invalid toml [%v]", cli.Args().Get(0))
						return
					}
				}

				if !ok {
					_, err = secrets.Create(s,
						secret.NewSecret().
							SetOrg(s.Options().OrgId).
							SetName(cli.Args().Get(0)),
						bytes.NewBuffer(next))
					return
				}

				_, err = secrets.Write(s, tmp.Update(), bytes.NewBuffer(next))
				return
			},
		})
)
