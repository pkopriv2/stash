package secret

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/mime"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/lang/term"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	ExecCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "exec",
			Usage: "exec <secret> <cmd> [<arg>]*",
			Info:  "Execute a command with a secret injected into the environment",
			Help: `
Execute a command with a secret injected into the environment.

Example:

	$ stash secret exec /project/dev npm run dev

`,
			Flags: tool.NewFlags(tool.VFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) < 2 {
					err = errors.Wrapf(errs.ArgError, "Expected a secret and a command")
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

				ptr := ref.Pointer(cli.Args().Get(0))
				var dec enc.Decoder
				switch ptr.Mime() {
				default:
					dec = enc.Yaml
				case mime.Json:
					dec = enc.Json
				case mime.Toml:
					dec = enc.Toml
				}

				buf := &bytes.Buffer{}
				if err = secrets.Read(s, sec.Secret, buf); err != nil {
					return
				}

				raw, err := ref.ReadObject(dec, buf.Bytes())
				if err != nil {
					return
				}

				obj, ok := raw.(ref.Map)
				if !ok {
					err = errors.Wrapf(errs.ArgError, "Only supports maps")
					return
				}

				// let's copy the current environment to make this behave sanely
				environ := make(map[string]string)
				for _, v := range os.Environ() {
					parts := strings.SplitN(v, "=", 2)
					environ[parts[0]] = parts[1]
				}

				for k, v := range obj {
					environ[k] = fmt.Sprint(v)
				}

				cmd, err := term.SystemShell.Start(env.Terminal.IO, cli.Args().Get(1),
					term.WithArgs(cli.Args()[2:]...),
					term.WithEnv(environ))
				if err != nil {
					err = errors.Wrapf(err, "Unable to launch command [%v]", cli.Args().Get(1))
					return
				}

				sig := make(chan os.Signal, 2)
				signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

				ctrl := context.NewRootControl()
				defer ctrl.Close()
				go func() {
					select {
					case <-sig:
						cmd.Process.Signal(syscall.SIGTERM)

						timer := time.After(5 * time.Second)
						select {
						case <-timer:
							cmd.Process.Signal(syscall.SIGKILL)
						case <-ctrl.Closed():
						}
					case <-ctrl.Closed():
					}
				}()

				err = cmd.Wait()
				return

			},
		})
)
