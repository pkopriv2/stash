package secret

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sdk/secrets"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var (
	CpCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "cp",
			Usage: "cp <src> <dst>",
			Info:  "Copy data streams",
			Help: `
Copy allows you to copy data streams.  The input to src
and destination may be:

* stdin/stdout  (e.g. -)
* secrets  (e.g. /secret.json)
* native files  (e.g. @file.txt)

Examples:

Copy a local file into a locker:

$ cp @file.json /secrets/file.txt

Copy a secret to your local machine:

$ cp /secrets/file.txt @file.txt

Copy from stdin:

$ echo 'hello, world' | cp - file.txt

Copy to stdout:

$ cp file.txt -
			`,
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) != 2 {
					err = errors.Wrap(errs.ArgError, "Must provide a source and destination")
					return
				}

				orig, next := cli.Args().Get(0), cli.Args().Get(1)

				s, err := session.NewDefaultSession(env.Context, env.Config)
				if err != nil {
					return err
				}
				defer s.Close()

				var src, dst secrets.IO
				switch {
				case orig == "-":
					src = secrets.StdIO{os.Stdin, os.Stdout}
				case strings.HasPrefix(orig, "@"):
					src = secrets.OpenNative(orig)
				case strings.HasPrefix(orig, "file://"):
					src = secrets.OpenNative(orig)
				case strings.HasPrefix(orig, "secret://"):
					src = secrets.OpenSecret(s, s.Options().OrgId, orig)
				default:
					src = secrets.OpenSecret(s, s.Options().OrgId, orig)
				}
				switch {
				case next == "-":
					dst = secrets.StdIO{os.Stdin, os.Stdout}
				case strings.HasPrefix(next, "@"):
					dst = secrets.OpenNative(next)
				case strings.HasPrefix(next, "file://"):
					dst = secrets.OpenNative(next)
				case strings.HasPrefix(next, "secret://"):
					dst = secrets.OpenSecret(s, s.Options().OrgId, next)
				default:
					dst = secrets.OpenSecret(s, s.Options().OrgId, next)
				}

				var r io.Reader
				r, w := io.Pipe()
				go func() {
					w.CloseWithError(src.Read(w))
				}()

				var bar *pb.ProgressBar
				if next != "-" {
					bar = pb.New(0)
					bar.Width = 80
					bar.ShowSpeed = true
					bar.AutoStat = true
					bar.Start()

					r = bar.NewProxyReader(r)
				}

				if err = dst.Write(r); err != nil {
					return
				}

				if bar != nil {
					bar.Finish()
				}

				if next != "-" {
					fmt.Fprintf(env.Terminal.IO.StdOut(), "\nSuccessfully copied secret [%v->%v]\n", orig, next)
				}
				return
			},
		})
)
