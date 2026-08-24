/*
 * net_fastpath.h — ownership-safe software queues for the native NIC path
 *
 * The queue core is deliberately hardware independent. net_pd is the only
 * component allowed to advance DRIVER/DEVICE ownership; clients can only
 * reserve FREE slots, submit CLIENT slots, and release completed slots.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NETFP_MAX_QUEUES       4u
#define NETFP_RING_SIZE       64u
#define NETFP_BATCH_MAX       32u
#define NETFP_FRAME_MAX     1514u

enum netfp_owner {
    NETFP_FREE = 0u,
    NETFP_CLIENT,
    NETFP_DRIVER,
    NETFP_DEVICE,
    NETFP_COMPLETE,
};

typedef struct {
    uint16_t len;
    uint8_t owner;
    uint8_t queue_id;
    uint32_t generation;
    uint64_t submitted_tick;
    uint64_t completed_tick;
} netfp_slot_t;

typedef struct {
    uint32_t reserve_head;
    uint32_t driver_tail;
    uint32_t complete_tail;
    uint32_t in_flight;
    netfp_slot_t slots[NETFP_RING_SIZE];
} netfp_queue_t;

typedef struct {
    netfp_queue_t queues[NETFP_MAX_QUEUES];
    uint32_t queue_count;
    uint32_t rr_next;
    uint64_t irq_count;
    uint64_t submitted;
    uint64_t completed;
    uint64_t backpressure;
    uint64_t batches;
    uint32_t max_batch;
} netfp_state_t;

static inline void netfp_fence(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline void netfp_init(netfp_state_t *state, uint32_t queue_count)
{
    if (queue_count == 0u || queue_count > NETFP_MAX_QUEUES)
        queue_count = 1u;
    *state = (netfp_state_t){0};
    state->queue_count = queue_count;
    for (uint32_t q = 0u; q < queue_count; q++) {
        for (uint32_t i = 0u; i < NETFP_RING_SIZE; i++) {
            state->queues[q].slots[i].owner = NETFP_FREE;
            state->queues[q].slots[i].queue_id = (uint8_t)q;
        }
    }
}

static inline uint32_t netfp_select_queue(netfp_state_t *state)
{
    uint32_t q = state->rr_next;
    state->rr_next = (q + 1u) % state->queue_count;
    return q;
}

static inline int netfp_client_reserve(netfp_state_t *state, uint32_t queue_id,
                                       uint32_t *slot_id)
{
    if (queue_id >= state->queue_count || slot_id == NULL)
        return -1;
    netfp_queue_t *queue = &state->queues[queue_id];
    uint32_t id = queue->reserve_head % NETFP_RING_SIZE;
    netfp_slot_t *slot = &queue->slots[id];
    if (__atomic_load_n(&slot->owner, __ATOMIC_ACQUIRE) != NETFP_FREE) {
        state->backpressure++;
        return -2;
    }
    slot->generation++;
    slot->len = 0u;
    __atomic_store_n(&slot->owner, NETFP_CLIENT, __ATOMIC_RELEASE);
    queue->reserve_head++;
    *slot_id = id;
    return 0;
}

static inline int netfp_client_submit(netfp_state_t *state, uint32_t queue_id,
                                      uint32_t slot_id, uint32_t len,
                                      uint64_t tick)
{
    if (queue_id >= state->queue_count || slot_id >= NETFP_RING_SIZE
        || len == 0u || len > NETFP_FRAME_MAX)
        return -1;
    netfp_slot_t *slot = &state->queues[queue_id].slots[slot_id];
    if (__atomic_load_n(&slot->owner, __ATOMIC_ACQUIRE) != NETFP_CLIENT)
        return -3;
    slot->len = (uint16_t)len;
    slot->submitted_tick = tick;
    netfp_fence();
    __atomic_store_n(&slot->owner, NETFP_DRIVER, __ATOMIC_RELEASE);
    state->submitted++;
    return 0;
}

static inline uint32_t netfp_driver_batch(netfp_state_t *state,
                                          uint32_t queue_id,
                                          uint32_t budget,
                                          uint32_t *slot_ids)
{
    if (queue_id >= state->queue_count || slot_ids == NULL)
        return 0u;
    if (budget > NETFP_BATCH_MAX) budget = NETFP_BATCH_MAX;
    netfp_queue_t *queue = &state->queues[queue_id];
    uint32_t count = 0u;
    while (count < budget) {
        uint32_t id = queue->driver_tail % NETFP_RING_SIZE;
        netfp_slot_t *slot = &queue->slots[id];
        if (__atomic_load_n(&slot->owner, __ATOMIC_ACQUIRE) != NETFP_DRIVER)
            break;
        __atomic_store_n(&slot->owner, NETFP_DEVICE, __ATOMIC_RELEASE);
        slot_ids[count++] = id;
        queue->driver_tail++;
        queue->in_flight++;
    }
    if (count > 0u) {
        state->batches++;
        if (count > state->max_batch) state->max_batch = count;
    }
    return count;
}

static inline int netfp_driver_complete(netfp_state_t *state,
                                        uint32_t queue_id, uint32_t slot_id,
                                        uint64_t tick)
{
    if (queue_id >= state->queue_count || slot_id >= NETFP_RING_SIZE)
        return -1;
    netfp_queue_t *queue = &state->queues[queue_id];
    netfp_slot_t *slot = &queue->slots[slot_id];
    if (__atomic_load_n(&slot->owner, __ATOMIC_ACQUIRE) != NETFP_DEVICE)
        return -3;
    slot->completed_tick = tick;
    netfp_fence();
    __atomic_store_n(&slot->owner, NETFP_COMPLETE, __ATOMIC_RELEASE);
    if (queue->in_flight > 0u) queue->in_flight--;
    state->completed++;
    return 0;
}

static inline int netfp_client_release(netfp_state_t *state,
                                       uint32_t queue_id, uint32_t slot_id)
{
    if (queue_id >= state->queue_count || slot_id >= NETFP_RING_SIZE)
        return -1;
    netfp_slot_t *slot = &state->queues[queue_id].slots[slot_id];
    if (__atomic_load_n(&slot->owner, __ATOMIC_ACQUIRE) != NETFP_COMPLETE)
        return -3;
    slot->len = 0u;
    netfp_fence();
    __atomic_store_n(&slot->owner, NETFP_FREE, __ATOMIC_RELEASE);
    state->queues[queue_id].complete_tail++;
    return 0;
}

static inline void netfp_record_irq(netfp_state_t *state)
{
    state->irq_count++;
}
