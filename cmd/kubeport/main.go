// kubeport opens a local HTTPS endpoint backed by a Kubernetes port-forward.
//
// It replaces the "kubectl port-forward + local reverse proxy + hosts edit"
// bootstrap script with a single, self-contained binary. The CA and leaf
// certificate are generated on the fly, the CA is installed into the OS
// trust store on first run (per-user), and the hosts entry is added and
// removed via brief UAC self-elevation.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/OWNER/kubeport/internal/admin"
	"github.com/OWNER/kubeport/internal/ca"
	"github.com/OWNER/kubeport/internal/hosts"
	"github.com/OWNER/kubeport/internal/kube"
	"github.com/OWNER/kubeport/internal/portforward"
	"github.com/OWNER/kubeport/internal/proxy"
	"github.com/OWNER/kubeport/internal/truststore"
)

// ensureHostsEntry adds `ip hostname` to the OS hosts file, self-elevating
// via UAC (Windows) or sudo (Unix) if the entry is missing and the
// process isn't already privileged. It returns a remover closure the
// caller must run on shutdown to take the entry back out. The remover
// only ever touches kubeport-tagged lines, so a pre-existing manual
// entry for the same hostname is left alone.
func ensureHostsEntry(ip, hostname string) (func() error, error) {
	present, err := hosts.HasEntry(ip, hostname)
	if err != nil {
		return nil, fmt.Errorf("hosts file: %w", err)
	}
	remover := makeHostsRemover(hostname)
	if present {
		fmt.Fprintf(os.Stdout, "[kubeport] hosts entry already present for %s\n", hostname)
		tagged, err := hosts.HasTaggedEntry(hostname)
		if err != nil {
			return nil, fmt.Errorf("hosts file: %w", err)
		}
		if tagged {
			return remover, nil
		}
		return nil, nil
	}

	if admin.IsElevated() {
		if _, err := hosts.Add(ip, hostname); err != nil {
			return nil, fmt.Errorf("hosts file: %w", err)
		}
		fmt.Fprintf(os.Stdout, "[kubeport] added hosts entry: %s %s\n", ip, hostname)
		return remover, nil
	}

	fmt.Fprintf(os.Stdout, "[kubeport] hosts entry missing; requesting admin elevation to add %s → %s …\n", hostname, ip)
	exit, err := elevateBootstrap([]string{"--host-ip", ip, "--host-name", hostname})
	if err != nil {
		return nil, fmt.Errorf("elevate to add hosts entry: %w", err)
	}
	if exit != 0 {
		return nil, fmt.Errorf("elevated helper exited with code %d", exit)
	}
	present, err = hosts.HasEntry(ip, hostname)
	if err != nil {
		return nil, fmt.Errorf("verify hosts entry: %w", err)
	}
	if !present {
		return nil, fmt.Errorf("hosts entry for %s was not added (UAC denied?)", hostname)
	}
	fmt.Fprintf(os.Stdout, "[kubeport] added hosts entry: %s %s\n", ip, hostname)
	return remover, nil
}

// makeHostsRemover returns a shutdown hook that deletes the kubeport-tagged
// hosts entry for hostname. On Unix it uses sudo; on Windows it self-elevates
// via UAC. Because writing to the hosts file always needs admin, this pops
// a second prompt on unprivileged sessions — startup + shutdown.
func makeHostsRemover(hostname string) func() error {
	return func() error {
		if admin.IsElevated() {
			if err := hosts.Remove(hostname); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "[kubeport] removed hosts entry for %s\n", hostname)
			return nil
		}
		fmt.Fprintf(os.Stdout, "[kubeport] requesting admin elevation to remove hosts entry for %s …\n", hostname)
		exit, err := elevateBootstrap([]string{"--host-name", hostname, "--remove"})
		if err != nil {
			return fmt.Errorf("elevate to remove hosts entry: %w", err)
		}
		if exit != 0 {
			return fmt.Errorf("elevated helper exited with code %d", exit)
		}
		fmt.Fprintf(os.Stdout, "[kubeport] removed hosts entry for %s\n", hostname)
		return nil
	}
}

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	kubeconfig  string
	contextName string
	namespace   string
	auth        string

	pod         string
	service     string
	targetPort  int
	servicePort string

	hostname   string
	localPort  int
	httpsPort  int
	path       string
	loopbackIP string

	skipHosts bool
	skipTrust bool
	noHTTPS   bool

	showVersion bool
}

func main() {
	// Hidden subcommand — used for self-relaunch under UAC to do the
	// narrow set of operations that require admin (hosts file).
	if len(os.Args) > 1 && os.Args[1] == "__bootstrap" {
		os.Exit(bootstrapMain(os.Args[2:]))
	}

	opts := parseFlags()
	if opts.showVersion {
		fmt.Printf("kubeport %s\n", version)
		return
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "kubeport: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() *options {
	opts := &options{}
	fs := flag.CommandLine
	fs.StringVar(&opts.kubeconfig, "kubeconfig", "", "path to kubeconfig (defaults to KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&opts.contextName, "context", "", "kubeconfig context name (defaults to current-context)")
	fs.StringVarP(&opts.namespace, "namespace", "n", "", "namespace (defaults to context namespace)")
	fs.StringVar(&opts.auth, "auth", "", "override kubelogin AAD login method: interactive|devicecode|azurecli|spn|workloadidentity|msi|ropc (sets AAD_LOGIN_METHOD)")

	fs.StringVar(&opts.pod, "pod", "", "pod name (mutually exclusive with --service)")
	fs.StringVar(&opts.service, "service", "", "service name (mutually exclusive with --pod)")
	fs.IntVar(&opts.targetPort, "target-port", 0, "pod container port (required with --pod; overrides service-resolved port)")
	fs.StringVar(&opts.servicePort, "service-port", "", "service port name or number to pick (default: first)")

	fs.StringVar(&opts.hostname, "hostname", "localhost", "hostname exposed locally (hosts file entry + TLS SAN)")
	fs.IntVar(&opts.localPort, "local-port", 8080, "local port for the port-forward tunnel")
	fs.IntVar(&opts.httpsPort, "https-port", 443, "local port the HTTPS proxy listens on")
	fs.StringVar(&opts.path, "path", "", "optional URL path appended to the ready URL (e.g. /evaluation-tool)")
	fs.StringVar(&opts.loopbackIP, "loopback-ip", "127.0.0.1", "loopback IP to point the hosts entry at")

	fs.BoolVar(&opts.skipHosts, "skip-hosts", false, "do not modify the OS hosts file")
	fs.BoolVar(&opts.skipTrust, "skip-trust", false, "do not install the local CA into the OS trust store")
	fs.BoolVar(&opts.noHTTPS, "no-https", false, "skip the HTTPS proxy and only run the port-forward")

	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")

	fs.Usage = usage
	flag.Parse()

	if flag.NArg() > 0 && opts.pod == "" && opts.service == "" {
		applyPositional(opts, flag.Arg(0))
	}

	return opts
}

func applyPositional(opts *options, arg string) {
	kind, name, ok := strings.Cut(arg, "/")
	if !ok {
		opts.pod = arg
		return
	}
	switch strings.ToLower(kind) {
	case "pod", "pods", "po":
		opts.pod = name
	case "service", "services", "svc":
		opts.service = name
	}
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, `kubeport %s — local HTTPS reverse proxy backed by a kubectl port-forward

Usage:
  kubeport [flags] pod/NAME      # forward to a named pod
  kubeport [flags] svc/NAME      # resolve ready pod from service selector

Examples:
  kubeport svc/my-service \
      --context my-cluster \
      --namespace my-namespace \
      --hostname app.local \
      --path /ui

  kubeport pod/my-pod --target-port 8080 --hostname app.local

Flags:
`, version)
	flag.PrintDefaults()
}

func run(opts *options) error {
	if opts.pod == "" && opts.service == "" {
		return errors.New("one of --pod or --service (or positional pod/NAME, svc/NAME) is required")
	}
	if opts.pod != "" && opts.service != "" {
		return errors.New("--pod and --service are mutually exclusive")
	}
	if opts.pod != "" && opts.targetPort == 0 {
		return errors.New("--target-port is required when using --pod")
	}

	// On Linux the HTTPS listener itself needs elevation for ports
	// below 1024 (Windows has no privileged-ports concept). Fail fast
	// there so users hit a clear error before kubelogin / az run as
	// root and mess up their token caches.
	if runtime.GOOS != "windows" && !opts.noHTTPS && opts.httpsPort < 1024 && !admin.IsElevated() {
		if runtime.GOOS == "darwin" {
			return fmt.Errorf("binding port %d requires root on macOS; pass --https-port >=1024, for example --https-port 8443", opts.httpsPort)
		}
		return fmt.Errorf("binding port %d requires root on %s; re-run under sudo or pass --https-port >=1024", opts.httpsPort, runtime.GOOS)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := newCleanup()
	defer cleanup.run()

	if opts.auth != "" {
		if err := os.Setenv("AAD_LOGIN_METHOD", opts.auth); err != nil {
			return fmt.Errorf("set AAD_LOGIN_METHOD: %w", err)
		}
		fmt.Fprintf(os.Stdout, "[kubeport] AAD_LOGIN_METHOD=%s (overrides kubeconfig exec-plugin login mode)\n", opts.auth)
	}

	kc, err := kube.LoadClient(opts.kubeconfig, opts.contextName, opts.namespace)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "[kubeport] context=%s namespace=%s\n", kc.ContextName, kc.Namespace)

	var target *kube.Target
	if opts.pod != "" {
		target, err = kc.ResolvePod(ctx, opts.pod, opts.targetPort)
	} else {
		target, err = kc.ResolveService(ctx, opts.service, opts.servicePort)
		if err == nil && opts.targetPort > 0 {
			target.TargetPort = opts.targetPort
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "[kubeport] forwarding to pod=%s targetPort=%d\n", target.PodName, target.TargetPort)

	var leafCert tls.Certificate
	if !opts.noHTTPS {
		leafCert, err = setupTLS(opts)
		if err != nil {
			return err
		}
	}

	if !opts.skipHosts && !opts.noHTTPS && opts.hostname != "" && opts.hostname != "localhost" {
		remover, err := ensureHostsEntry(opts.loopbackIP, opts.hostname)
		if err != nil {
			return err
		}
		if remover != nil {
			cleanup.push("remove hosts entry", remover)
		}
	}

	// Build the port-forward listener. In HTTPS mode it's an authenticated
	// IPC endpoint (UDS on POSIX, named pipe on Windows) so other local
	// processes can't bypass the TLS terminator by dialing the upstream.
	// In --no-https mode we keep TCP loopback for backwards compatibility
	// with scripted / non-browser clients.
	var (
		tunnelListener net.Listener
		upstreamDial   proxy.DialFunc
		tunnelDesc     string
	)
	if opts.noHTTPS {
		addr := fmt.Sprintf("%s:%d", opts.loopbackIP, opts.localPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("bind tunnel %s: %w", addr, err)
		}
		tunnelListener = ln
		tunnelDesc = addr
	} else {
		endpoint, err := portforward.DefaultIPCEndpoint()
		if err != nil {
			return fmt.Errorf("ipc endpoint: %w", err)
		}
		ln, err := portforward.ListenIPC(endpoint)
		if err != nil {
			return fmt.Errorf("listen ipc %s: %w", endpoint, err)
		}
		tunnelListener = ln
		tunnelDesc = endpoint
		upstreamDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return portforward.DialIPC(ctx, endpoint)
		}
	}

	pfw := portforward.New(
		kc.Config, kc.Clientset,
		target.Namespace, target.PodName,
		tunnelListener, target.TargetPort,
		io.Discard, os.Stderr,
	)
	if err := pfw.Start(ctx); err != nil {
		return fmt.Errorf("port-forward: %w", err)
	}
	cleanup.push("stop port-forward", func() error { pfw.Stop(); return nil })
	fmt.Fprintf(os.Stdout, "[kubeport] port-forward ready: %s → %s:%d\n", tunnelDesc, target.PodName, target.TargetPort)

	var proxyErrCh <-chan error
	if !opts.noHTTPS {
		px := proxy.New(
			fmt.Sprintf("%s:%d", opts.loopbackIP, opts.httpsPort),
			upstreamDial,
			opts.hostname,
			leafCert,
		)
		ch, err := px.Start()
		if err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
		proxyErrCh = ch
		cleanup.push("stop https proxy", func() error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return px.Stop(shutdownCtx)
		})

		readyURL := buildReadyURL(opts.hostname, opts.httpsPort, opts.path)
		fmt.Fprintf(os.Stdout, "\n[kubeport] ready: %s\n\n", readyURL)
	} else {
		fmt.Fprintf(os.Stdout, "\n[kubeport] ready: http://127.0.0.1:%d (no HTTPS proxy)\n\n", opts.localPort)
	}

	fmt.Fprintln(os.Stdout, "[kubeport] press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case s := <-sigCh:
		fmt.Fprintf(os.Stdout, "\n[kubeport] received %s, shutting down…\n", s)
	case err := <-pfw.Err():
		if err != nil {
			fmt.Fprintf(os.Stderr, "[kubeport] port-forward exited: %v\n", err)
		}
	case err := <-proxyErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "[kubeport] proxy exited: %v\n", err)
		}
	}
	return nil
}

func setupTLS(opts *options) (tls.Certificate, error) {
	var empty tls.Certificate

	localCA, err := ca.LoadOrCreate()
	if err != nil {
		return empty, fmt.Errorf("ca: %w", err)
	}

	if !opts.skipTrust {
		if !truststore.IsInstalled(localCA.Cert) {
			fmt.Fprintf(os.Stdout, "[kubeport] installing local CA into trust store (first run)…\n")
			if err := truststore.Install(localCA.Cert, localCA.CertPath); err != nil {
				return empty, fmt.Errorf("trust store: %w", err)
			}
			fmt.Fprintf(os.Stdout, "[kubeport] CA installed\n")
		}
	}

	sans := dedupe([]string{opts.hostname, "localhost", "127.0.0.1"})
	cert, err := localCA.IssueLeaf(sans)
	if err != nil {
		return empty, fmt.Errorf("issue leaf cert: %w", err)
	}
	return cert, nil
}

func buildReadyURL(host string, port int, path string) string {
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	if port != 443 {
		u.Host = fmt.Sprintf("%s:%d", host, port)
	}
	return u.String()
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
