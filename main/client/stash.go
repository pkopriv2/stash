package main

import (
	"fmt"
	"os"

	"github.com/cott-io/stash/cli/client/account"
	"github.com/cott-io/stash/cli/client/group"
	"github.com/cott-io/stash/cli/client/identity"
	"github.com/cott-io/stash/cli/client/member"
	"github.com/cott-io/stash/cli/client/org"
	"github.com/cott-io/stash/cli/client/secret"
	"github.com/cott-io/stash/lang/tool"
)

// This variable is to set versioning during the build process using the following build command
// go build -i -v -ldflags "main.version=${RELEASE_VERSION}" -o $rel/$BUILD_BINARY $BUILD_SOURCE/$BUILD_MAIN
var version string = "default"

var (
	MainTool = tool.NewTool(
		tool.ToolDef{
			Name:    "stash",
			Version: version,
			Usage:   "stash [cmd] [arg]*",
			Desc: `
Stash is a secret management platform.
`,
		},
		account.SetupCommand,
		account.RecoverCommand,
		identity.Commands,
		org.Commands,
		member.Commands,
		group.Commands,
		secret.Commands,
	)
)

func main() {
	env, err := tool.NewDefaultEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize environment: %v\n", err)
		os.Exit(1)
		return
	}

	defer fmt.Println()
	if err := tool.Run(env, MainTool, os.Args); err != nil {
		os.Exit(1)
		return
	}
}
