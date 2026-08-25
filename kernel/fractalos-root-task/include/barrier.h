/*
 * FractalOS — Architecture-portable memory barrier macros
 *
 * Usage:
 *   fractalos_wmb()  — write (store) memory barrier
 *   fractalos_rmb()  — read (load) memory barrier
 *   fractalos_mb()   — full memory barrier (read + write)
 *
 * These are architecture-specific:
 *   RISC-V:  fence instructions
 *   AArch64: dmb (data memory barrier) instructions
 *   x86_64:  sfence/lfence/mfence (x86 is strongly ordered, but
 *            sfence is needed for non-temporal stores and to prevent
 *            compiler reordering; mfence for full serialization)
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#if defined(__riscv)

#define fractalos_wmb()  __asm__ volatile ("fence w,w" ::: "memory")
#define fractalos_rmb()  __asm__ volatile ("fence r,r" ::: "memory")
#define fractalos_mb()   __asm__ volatile ("fence rw,rw" ::: "memory")

#elif defined(__aarch64__)

#define fractalos_wmb()  __asm__ volatile ("dmb ishst" ::: "memory")
#define fractalos_rmb()  __asm__ volatile ("dmb ishld" ::: "memory")
#define fractalos_mb()   __asm__ volatile ("dmb ish" ::: "memory")

#elif defined(__x86_64__)

#define fractalos_wmb()  __asm__ volatile ("sfence" ::: "memory")
#define fractalos_rmb()  __asm__ volatile ("lfence" ::: "memory")
#define fractalos_mb()   __asm__ volatile ("mfence" ::: "memory")

#else

/* Unknown architecture — compiler barrier only (safe but weaker) */
#define fractalos_wmb()  __asm__ volatile ("" ::: "memory")
#define fractalos_rmb()  __asm__ volatile ("" ::: "memory")
#define fractalos_mb()   __asm__ volatile ("" ::: "memory")

#endif
