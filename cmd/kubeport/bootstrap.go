package main

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"

	"github.com/OWNER/kubeport/internal/hosts"
)

// bootstrapMain runs when the binary is re-invoked under elevated
// privileges via the hidden "__bootstrap" subcommand. It performs the
// minimum set of operations that require admin (writing the system
// hosts file) and exits. It never touches the main flag set.
func bootstrapMain(args []string) int {
	fs := flag.NewFlagSet("__bootstrap", flag.ContinueOnError)
	var (
		hostIP   string
		hostName string
		remove   bool
	)
	fs.StringVar(&hostIP, "host-ip", "", "hosts-entry IP (e.g. 127.0.0.1)")
	fs.StringVar(&hostName, "host-name", "", "hosts-entry hostname (e.g. app.local)")
	fs.BoolVar(&remove, "remove", false, "remove the kubeport-tagged hosts entry instead of adding it")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if remove {
		if hostName == "" {
			fmt.Fprintln(os.Stderr, "--host-name is required with --remove")
			return 2
		}
		if err := hosts.Remove(hostName); err != nil {
			fmt.Fprintf(os.Stderr, "remove host: %v\n", err)
			return 1
		}
		return 0
	}

	if hostIP != "" && hostName != "" {
		if _, err := hosts.Add(hostIP, hostName); err != nil {
			fmt.Fprintf(os.Stderr, "add host: %v\n", err)
			return 1
		}
	}
	return 0
}
