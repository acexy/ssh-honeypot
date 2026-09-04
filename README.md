# SSH Honeypot

SSH Honeypot is a lightweight Go service for observing automated SSH scans, password-guessing attempts, and malicious client behavior. It is a deception and telemetry component, not a real remote-login service.

<img src="https://raw.githubusercontent.com/acexy/ssh-honeypot/refs/heads/main/.github/workflows/type1.gif" />
<img src="https://raw.githubusercontent.com/acexy/ssh-honeypot/refs/heads/main/.github/workflows/type2.gif" />

## Current capabilities

- Listens on TCP port `22` by default.
- Accepts or rejects connections through an admission component.
- Performs SSH identification exchange and presents an OpenSSH/Ubuntu-style server banner.
- Applies an immediate or three-second randomized banner response delay.
- Validates client identification strings beginning with `SSH-`.
- Supports a pluggable password-authentication strategy; the default accepts the built-in demonstration password.
- Generates an RSA host key in memory at process startup.
- Discards global SSH requests and closes the connection after SSH negotiation.

The current implementation does not provide an interactive shell, command execution, SFTP, session recording, persistent event storage, runtime configuration, or graceful shutdown. See [`docs/requirements-analysis.md`](docs/requirements-analysis.md) for the prioritized roadmap.

## Quick start

Download a release from [GitHub Releases](https://github.com/acexy/ssh-honeypot/releases), or run from source:

```bash
go run ./cmd/main.go
```

Build a static Linux/amd64 binary:

```bash
make build
```

Create a release archive with custom metadata:

```bash
make package VERSION=dev OS=linux ARCH=amd64
```

The service listens on port `22`, so local or containerized testing may require a disposable port mapping or appropriate privileges.

## Extending the service

The `core/types` interfaces define extension points for connection admission, version exchange, SSH settings, and authentication. Implement a custom handler and compose it with `core.NewHoneypot` rather than changing the default components in place.

## Security boundary

This project must remain isolated from the host. It does not use system users, PAM, shadow files, or real SSH configuration, and it must never execute shell commands. Keep deployments isolated, avoid exposing the service on production administration ports, and do not commit credentials, private keys, or captured attacker data.

## License

See [LICENSE](LICENSE).
