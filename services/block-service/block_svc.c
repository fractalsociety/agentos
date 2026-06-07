/*
 * services/block-service/block_svc.c — Block/Disk Service stub
 *
 * Stub implementation. Returns SEL4_ERR_NOT_SUPPORTED to all callers.
 * Full implementation: contracts/block-service/interface.h
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>

typedef unsigned long seL4_CPtr;

__attribute__((noreturn)) void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)my_ep;
    (void)ns_ep;
    for (;;) { __asm__ volatile (""); }
}
