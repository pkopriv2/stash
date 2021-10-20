package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"

	"github.com/cott-io/stash/cli/server"
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
		server.RunCommand,
	)
)

func main() {
	// go http.ListenAndServe(":8881", http.DefaultServeMux)

	env, err := tool.NewDefaultEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize environment: %v\n", err)
		os.Exit(1)
		return
	}

	defer fmt.Println()
	if err := tool.Run(env, MainTool, os.Args); err != nil {
		defer os.Exit(1)
		return
	}
}
