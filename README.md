# kubeport

A single self-contained Go binary that opens a local HTTPS endpoint backed
by an in-process `kubectl port-forward`. It replaces the common
"kubectl port-forward + local reverse proxy + hosts file edit" bootstrap
script with one executable that just works.

**Why a binary?**

- Single `.exe`, zero external downloads — no reverse-proxy binary, no PowerShell script.
- Port-forward runs **in-process** via `client-go` (no `kubectl` child process).
- Local CA generated once, installed into the user's trust store (no admin), leaf
  certs issued per run — no browser cert warnings.
- Proper signal handling — Ctrl+C tears down the tunnel cleanly.
- Cross-compiles from macOS/Linux for Windows and macOS.
- Works for any namespace, pod, service, hostname, port, or cluster.
- Runs as your regular user — UAC is used only for the hosts file add/remove
  operations.

## Install

Grab the latest `kubeport-windows-amd64.exe` from the
[releases page](https://github.com/OWNER/kubeport/releases) and put it
anywhere on `PATH`. That's it.

## Usage

Run from a normal PowerShell window (no "Run as Administrator" needed).
kubeport will self-elevate via UAC only when it has to add or remove a hosts
entry — and only for a fraction of a second.

```powershell
kubeport svc/my-service `
  --context   my-cluster `
  --namespace my-namespace `
  --hostname  app.local `
  --path      /ui
```

Expected output on first run:

```
[kubeport] context=my-cluster namespace=my-namespace
[kubeport] forwarding to pod=my-service-abc123 targetPort=8080
[kubeport] installing local CA into trust store (first run)…
[kubeport] CA installed
[kubeport] hosts entry missing; requesting admin elevation to add app.local → 127.0.0.1 …
   (UAC prompt ← click Yes)
[kubeport] added hosts entry: 127.0.0.1 app.local (removed on shutdown)
[kubeport] port-forward ready: localhost:8080 → my-service-abc123:8080

[kubeport] ready: https://app.local/ui

[kubeport] press Ctrl+C to stop.
```

Press **Ctrl+C** to tear down the tunnel. The hosts entry is removed on
shutdown; the CA is left in place so subsequent runs do not need to reinstall
trust.

## More examples

```powershell
# Specific pod on port 9000
kubeport pod/my-pod --target-port 9000 --hostname app.local

# Different kubeconfig + context
kubeport svc/api `
  --kubeconfig C:\kube\custom.yaml `
  --context    prod-east `
  --namespace  payments `
  --hostname   api.local

# Just a port-forward, no HTTPS proxy
kubeport svc/api --no-https --local-port 9090

# macOS without sudo for the HTTPS listener
kubeport svc/api --hostname app.local --https-port 8443

# Azure AKS with AAD auth — force interactive login (opens browser)
kubeport svc/api --auth interactive --hostname app.local

# Azure AKS without a browser — device-code flow
kubeport svc/api --auth devicecode --hostname app.local
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--context` | current-context | kubeconfig context |
| `--namespace`, `-n` | context default | namespace |
| `--kubeconfig` | `$KUBECONFIG` → `~/.kube/config` | kubeconfig path |
| `--auth` | — | Override AAD login method for kubelogin: `interactive`, `devicecode`, `azurecli`, `spn`, `workloadidentity`, `msi`, `ropc` (sets `AAD_LOGIN_METHOD`) |
| `--pod` | — | pod name (requires `--target-port`) |
| `--service` | — | service name (target port auto-resolved) |
| `--target-port` | — | container port (required with `--pod`) |
| `--service-port` | first | service port name/number to pick |
| `--hostname` | `localhost` | hostname exposed locally (TLS SAN + hosts entry) |
| `--local-port` | `8080` | local port the tunnel binds to |
| `--https-port` | `443` | HTTPS proxy listen port |
| `--path` | — | URL path appended to the ready URL |
| `--loopback-ip` | `127.0.0.1` | loopback IP the hosts entry points at |
| `--skip-hosts` | false | don't modify the hosts file |
| `--skip-trust` | false | don't install the local CA |
| `--no-https` | false | skip HTTPS proxy (plain port-forward only) |
| `--version` | — | print version and exit |

Positional shortcuts `pod/NAME` and `svc/NAME` are equivalent to the
explicit flags.

## Traffic flow

```
Browser
  → https://app.local:443                               (hosts file: 127.0.0.1)
      → kubeport proxy (TLS termination, local CA leaf)
          → 127.0.0.1:8080                              (in-process SPDY tunnel)
              → kube-apiserver
                  → pod:8080
```

Everything except the pod runs inside the single `kubeport.exe` process.

## Elevation model

kubeport runs as the invoking user by default. Three operations have
historically needed admin; here's how each is handled now:

| Operation | Needs admin? | How kubeport handles it |
| --- | --- | --- |
| Bind port 443 | No on Windows; yes on macOS/Linux | Windows: runs in-process. macOS/Linux: fail fast with a clear message, suggesting `sudo` or `--https-port >=1024`. |
| Install local CA | No on Windows; user approval may be requested on macOS | Windows: `certutil.exe -user -addstore Root` → CurrentUser\Root store. macOS: `security add-trusted-cert` → current user's login keychain. |
| Edit hosts file | Yes, always | Windows self-elevates via UAC (`ShellExecuteExW` with verb `runas`). macOS/Linux use `sudo`. kubeport appends one tagged line at startup and removes it at shutdown. |

Net result: UAC prompts are limited to the brief hosts-file helper at startup
and shutdown. The hosts entry is tagged `# kubeport` so cleanup removes only
lines this tool wrote.

## Trust store

On first run, kubeport generates an ECDSA P-256 CA and installs it into
the OS trust store for the current user. On Windows this is the
**Current User → Trusted Root Certification Authorities** store via
`certutil.exe -user -addstore -f Root`. On macOS this is the user's login
keychain via `security add-trusted-cert`.

The CA material lives in the user's config directory (`%LOCALAPPDATA%\kubeport\`
on Windows, `~/Library/Application Support/kubeport/` on macOS):

```
kubeport-ca.crt      # public CA cert (also in the CurrentUser\Root store)
kubeport-ca.key      # EC private key, 0600
```

To remove the CA (e.g. when uninstalling):

```powershell
# Windows: show thumbprint
certutil -user -store Root | Select-String "kubeport"
# Windows: remove by thumbprint
certutil -user -delstore Root <thumbprint>
# delete on-disk material
Remove-Item -Recurse "$env:LOCALAPPDATA\kubeport"
# remove hosts entry (admin required)
# edit C:\Windows\System32\drivers\etc\hosts and delete the `# kubeport` line
```

## Build

Requires **Go 1.26** or newer.

```bash
# From macOS/Linux — produces dist/kubeport-windows-{amd64,arm64}.exe
make windows

# macOS arm64
make darwin

# Or directly:
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=$(git rev-parse --short HEAD)" \
  -o dist/kubeport.exe ./cmd/kubeport
```

The binary is fully static (`CGO_ENABLED=0`) — no DLL dependencies beyond
baseline Windows system libraries (`shell32.dll` for UAC elevation,
`certutil.exe` for trust store operations).

## Layout

```
kubeport/
├── cmd/kubeport/                 # CLI entrypoint
│   ├── main.go
│   ├── bootstrap.go              # hidden __bootstrap subcommand
│   ├── cleanup.go
│   ├── elevate_windows.go        # UAC helper (ShellExecuteExW)
│   └── elevate_unix.go           # sudo fallback
├── internal/
│   ├── admin/                    # elevation check (per-OS)
│   ├── ca/                       # local ECDSA P-256 CA + leaf issuance
│   ├── hosts/                    # hosts file add/remove/check
│   ├── kube/                     # kubeconfig + pod/service resolution
│   ├── portforward/              # in-process SPDY port-forward
│   ├── proxy/                    # HTTPS reverse proxy
│   └── truststore/               # Windows/macOS trust store integration
├── scripts/build.sh
├── Makefile
├── go.mod
├── LICENSE
└── README.md
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `bind 127.0.0.1:443: permission denied` | port already in use (IIS, Skype, etc.) | `netstat -ano \| findstr :443` → stop the offender, or pass `--https-port 8443` |
| `no ready pods matching service …` | deployment down / wrong namespace | `kubectl get pods -n <ns>` to verify |
| Certificate warning in browser | CA install blocked, or browser has its own NSS store (Firefox) | Chrome/Edge: re-run without `--skip-trust`. Firefox: import `%LOCALAPPDATA%\kubeport\kubeport-ca.crt` manually. |
| Hostname resolves externally instead of locally | hosts entry not written or DNS cache stale | `ipconfig /flushdns`; confirm the `# kubeport`-tagged line is present in the hosts file |
| `port-forward exited: error upgrading connection` | kubeconfig expired / wrong context | `kubectl config get-contexts`; re-auth |
| `failed to connect to localhost:<port> inside namespace` | The pod is Ready through its pod IP, but the container is not listening on loopback; Kubernetes pod port-forward has the same limitation | Pick a service whose container listens on `0.0.0.0`/loopback, or fix the app container bind address. Confirm with `kubectl port-forward`. |
| `kubelogin: executable not found` | kubelogin not on PATH of the account running kubeport | `az aks install-cli` to install it into the current user's PATH |

## License

MIT. See [LICENSE](LICENSE).
