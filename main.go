// Command weix explains Windows Event IDs in a SOC-friendly format.
package main

import (
	"os"

	"github.com/MrWaifu24/weix/cmd"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cmd.Execute(version))
}
