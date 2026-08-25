#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Ed25519 + SHA-256 WASM module verifier
 *
 * VIBE_VERIFY_MODE compile flag:
 *   -DVIBE_VERIFY_MODE=1  → production: reject loads with bad/missing sig (return false)
 *   -DVIBE_VERIFY_MODE=0  → dev mode: log warning but return true
 *   Default (undefined):  → dev mode
 *
 * Returns true if signature is valid (or dev mode with missing/bad sig).
 * Returns false only in production mode with bad/missing signature.
 */
bool vibe_verify_module(const uint8_t *wasm, size_t len, const uint8_t *trusted_pubkey);

/* Raw Ed25519 verification over an arbitrary-length message.
 * sig[64]: R||S signature bytes; msg/msg_len: message; pk[32]: public key.
 * Returns 0 on success, -1 on failure.
 */
int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                   const uint8_t pk[32]);

/*
 * verify_capabilities_manifest - check that the fractalos.cap_signature section
 * (SHA-256 digest, 32 bytes) matches a fresh SHA-256 of the fractalos.capabilities
 * section bytes.
 *
 * Returns  0  success — manifest is authentic.
 *         -1  required sections missing (no capabilities manifest present).
 *         -2  hash mismatch — manifest has been tampered.
 */
int verify_capabilities_manifest(const uint8_t *wasm, size_t wasm_len);

/* ─────────────────────────────────────────────────────────────────────────
 * FATAL cryptographic selftest gate.
 *
 * crypto_selftest() runs the Ed25519 verifier against pinned RFC 8032
 * known-answer vectors AND a known-BAD vector.  It is a HARD boot/test gate:
 * the controller MUST refuse to continue booting if it returns nonzero (see
 * the FATAL selftest gate in monitor.c::controller_main, which halts on
 * failure).  It is NOT a soft warning.
 *
 * Returns 0 iff:
 *   • the known-GOOD RFC 8032 signature verifies, AND
 *   • the known-BAD (corrupted) signature is correctly REJECTED, AND
 *   • the local sign + public-key-derivation round-trips reproduce the
 *     pinned RFC 8032 outputs.
 * Returns nonzero on ANY discrepancy — meaning the crypto stack is broken and
 * the boot/test gate must abort.
 */
int crypto_selftest(void);

/* Test-only hook: run the gate's known-good + known-bad logic against
 * caller-supplied vectors so a host test can force a failure path.
 * The supplied vectors are treated as the "known-good" pair; the function
 * additionally derives a corrupted copy and requires it to be rejected.
 * Returns 0 iff the supplied pair verifies AND its corrupted form is rejected. */
int crypto_selftest_with_vectors(const uint8_t sig[64], const uint8_t *msg,
                                 size_t msg_len, const uint8_t pk[32]);
