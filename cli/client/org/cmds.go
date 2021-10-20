package org

import "github.com/cott-io/stash/lang/tool"

var (
	Commands = tool.NewGroup(
		tool.GroupDef{
			Name: "org",
			Info: "Manage your organizations",
		},
		BuyCommand,
		UseCommand,
		LsCommand,
		RmCommand,
	)
)
