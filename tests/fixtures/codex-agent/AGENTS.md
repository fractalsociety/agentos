# FractalOS Codex E2E fixture

Use `fractalos_pool_status` exactly once for live capacity. Change only
`agent_health.c`, then run `make test`. Never invoke `agentctl` or a
control-plane socket from a shell command.
