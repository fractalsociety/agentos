# Local Gateway Contract

**Issue:** `fos-gz0.14.10.5`  
**Version:** 1  
**Opcodes:** `MSG_LOCAL_GATEWAY_*` (`0x3401`–`0x3406`) in `fractalos.h`  
**Header:** `contracts/local-gateway/interface.h`  
**Kernel mirror:** `kernel/fractalos-root-task/include/contracts/local_gateway_contract.h`

## Role

The Local Gateway is the **external typed fence** between:

1. Sibling companion apps / guest-hosted gateways (HTTPS, TLS, pages — **outside** this repo)
2. FractalOS companion-export projections, shared-space roots, and CapBroker grants

It does **not** render UI. It publishes expiring service capabilities, opens
sessions pinned to immutable shared roots + event ranges, serves a daily
workspace read model, and accepts only narrowly granted task intents.

## Operations

| Opcode | Name | Purpose |
|--------|------|---------|
| `0x3401` | `PUBLISH_SERVICE` | Mint expiring service capability + effect-ledger event |
| `0x3402` | `REVOKE_SERVICE` | Invalidate sessions; block derived child publications |
| `0x3403` | `OPEN_SESSION` | Bind session to service grants + pinned shared root |
| `0x3404` | `GET_DAILY` | Query one pinned daily workspace |
| `0x3405` | `SUBMIT_INTENT` | Only mutation path; requires `TASK_INTENT` grant |
| `0x3406` | `STATUS` | Service/session status including revoked flag |

## Authority rules

- Grant mask may only contain `LOCAL_GATEWAY_GRANT_*` bits.
- Any `LOCAL_GATEWAY_AMBIENT_*` bit → `LOCAL_GATEWAY_ERR_AMBIENT_DENIED`.
- Revoked parent → `LOCAL_GATEWAY_ERR_DERIVE_DENIED` / `REVOKED` on children and sessions.
- Expired `expires_unix_ms` → `LOCAL_GATEWAY_ERR_EXPIRED`.
- Missing daily/intent grant → `LOCAL_GATEWAY_ERR_NO_GRANT`.

## Proof boundary

- **In scope for 10.5:** contract + host L2 tests (daily + intent + revoke/derive).
- **Out of scope:** HTTP/3, TLS, HTML/CSS/JS, sibling `fractalos-companion` pages (`14.18`), live gateway PD (`14.17`).
