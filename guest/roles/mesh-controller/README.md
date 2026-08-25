# FractalOS mesh-controller guest role

This role installs Headscale 0.29.3 as a first-class FreeBSD service. AMD64
uses the pinned upstream binary; AArch64 builds the pinned source because the
upstream release does not publish a FreeBSD ARM64 asset. Both paths verify
SHA-256 before installation.

State lives in `/var/db/headscale` using SQLite WAL. Noise/TLS/DERP keys live
under `/var/db/fractalos-secrets/headscale` with mode 0700 and are never placed in
the guest-role image. Headscale policy and `netcap-map.json` are deny-by-default
and map authenticated tailnet tags to FractalOS NetCap classes.

The FreeBSD installer bootstrap stages this directory into the guest and runs
`install.sh` once networking is available. Standard Tailscale clients join with
the server URL and a short-lived pre-auth key created through `agentctl mesh`.
The default endpoint is `https://mesh.fractalos.internal:8080`; publish that DNS
name and install the generated `tls.crt` as a trusted CA on joining devices, or
replace `tls.crt` and `tls.key` with a certificate issued by their existing
trust store before enrollment.
