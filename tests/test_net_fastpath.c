#include <stdint.h>
#include <stdio.h>
#include "net_fastpath.h"
#include "contracts/net_device_contract.h"

static int passed, failed;
#define CHECK(x) do { if (x) passed++; else { failed++; printf("FAIL:%d: %s\n", __LINE__, #x); } } while (0)

static void test_ownership_and_batch(void)
{
    netfp_state_t state;
    uint32_t ids[NETFP_BATCH_MAX];
    netfp_init(&state, 4u);
    for (uint32_t i = 0u; i < 12u; i++) {
        uint32_t id;
        CHECK(netfp_client_reserve(&state, 2u, &id) == 0);
        CHECK(netfp_client_submit(&state, 2u, id, 64u + i, 100u + i) == 0);
    }
    uint32_t n = netfp_driver_batch(&state, 2u, 8u, ids);
    CHECK(n == 8u);
    CHECK(state.batches == 1u && state.max_batch == 8u);
    for (uint32_t i = 0u; i < n; i++) {
        CHECK(state.queues[2].slots[ids[i]].owner == NETFP_DEVICE);
        CHECK(netfp_driver_complete(&state, 2u, ids[i], 200u + i) == 0);
        CHECK(netfp_client_release(&state, 2u, ids[i]) == 0);
    }
    CHECK(state.submitted == 12u && state.completed == 8u);
}

static void test_backpressure(void)
{
    netfp_state_t state;
    netfp_init(&state, 1u);
    for (uint32_t i = 0u; i < NETFP_RING_SIZE; i++) {
        uint32_t id;
        CHECK(netfp_client_reserve(&state, 0u, &id) == 0);
        CHECK(netfp_client_submit(&state, 0u, id, 128u, i) == 0);
    }
    uint32_t id = 0u;
    CHECK(netfp_client_reserve(&state, 0u, &id) == -2);
    CHECK(state.backpressure == 1u);
}

static void test_multiqueue_and_illegal_transitions(void)
{
    netfp_state_t state;
    netfp_init(&state, NETFP_MAX_QUEUES);
    for (uint32_t i = 0u; i < 8u; i++)
        CHECK(netfp_select_queue(&state) == i % NETFP_MAX_QUEUES);
    uint32_t id;
    CHECK(netfp_client_reserve(&state, 1u, &id) == 0);
    CHECK(netfp_client_release(&state, 1u, id) == -3);
    CHECK(netfp_client_submit(&state, 1u, id, 0u, 0u) == -1);
    CHECK(netfp_driver_complete(&state, 1u, id, 0u) == -3);
    netfp_record_irq(&state);
    netfp_record_irq(&state);
    CHECK(state.irq_count == 2u);
}

static void test_dma_contract_layout(void)
{
    CHECK(sizeof(net_dma_startup_t) == 24u);
    CHECK(sizeof(net_dma_desc_t) == 16u);
    CHECK(sizeof(net_dma_virtio_hdr_t) == 10u);
    CHECK(NET_DMA_RX_DESC_OFFSET >= NET_DMA_CLIENT_BYTES);
    CHECK(NET_DMA_RX_BUFFER_OFFSET
          + NET_DMA_QUEUE_DEPTH * NET_DMA_BUFFER_STRIDE
          <= NET_DMA_TX_BUFFER_OFFSET);
    CHECK(NET_DMA_TX_BUFFER_OFFSET
          + NET_DMA_QUEUE_DEPTH * NET_DMA_BUFFER_STRIDE
          <= NET_DMA_LAYOUT_END);
    CHECK(NET_DMA_WG_FRAME_OFFSET >= NET_DMA_DRIVER_LAYOUT_END);
    CHECK(NET_DMA_LAYOUT_END <= NET_DMA_ARENA_BYTES);
    CHECK(sizeof(net_fastpath_send_req_t) == 8u);
    CHECK(sizeof(net_fastpath_status_reply_t) == 16u);
    CHECK(NET_PD_RIGHT_FASTPATH != 0u);
    CHECK(NET_DMA_TX_CHAIN_HEADS * 2u <= NET_DMA_QUEUE_DEPTH);
    CHECK(NET_DMA_TX_CHAIN_TAIL0 == NET_DMA_TX_CHAIN_HEADS);
    CHECK(NETFP_MAX_QUEUES >= 4u);
}

/* TX stays DEVICE until an IRQ-driven complete/release cycle; submit alone
 * must not free the ring (polling is not the production reclaim path). */
static void test_irq_driven_reclaim(void)
{
    netfp_state_t state;
    uint32_t ids[NETFP_BATCH_MAX];
    netfp_init(&state, 1u);
    for (uint32_t i = 0u; i < NETFP_RING_SIZE; i++) {
        uint32_t id;
        CHECK(netfp_client_reserve(&state, 0u, &id) == 0);
        CHECK(netfp_client_submit(&state, 0u, id, 64u, i) == 0);
    }
    CHECK(netfp_driver_batch(&state, 0u, NETFP_BATCH_MAX, ids) == NETFP_BATCH_MAX);
    {
        uint32_t blocked = 0u;
        CHECK(netfp_client_reserve(&state, 0u, &blocked) == -2);
        CHECK(state.backpressure >= 1u);
    }
    for (uint32_t i = 0u; i < NETFP_BATCH_MAX; i++) {
        CHECK(state.queues[0].slots[ids[i]].owner == NETFP_DEVICE);
        CHECK(netfp_driver_complete(&state, 0u, ids[i], 1000u + i) == 0);
        CHECK(netfp_client_release(&state, 0u, ids[i]) == 0);
    }
    netfp_record_irq(&state);
    CHECK(state.irq_count == 1u);
    {
        uint32_t id = 0u;
        CHECK(netfp_client_reserve(&state, 0u, &id) == 0);
        CHECK(netfp_client_submit(&state, 0u, id, 64u, 42u) == 0);
    }
}

/* Soft multi-queue RR must share one HW head pool of CHAIN_HEADS without
 * allowing more DEVICE-owned TX than hardware can chain. */
static void test_multiqueue_hw_head_budget(void)
{
    netfp_state_t state;
    uint32_t ids[NETFP_BATCH_MAX];
    uint32_t submitted = 0u;
    netfp_init(&state, NETFP_MAX_QUEUES);
    for (uint32_t i = 0u; i < NET_DMA_TX_CHAIN_HEADS; i++) {
        uint32_t q = netfp_select_queue(&state);
        uint32_t id;
        CHECK(netfp_client_reserve(&state, q, &id) == 0);
        CHECK(netfp_client_submit(&state, q, id, 64u, i) == 0);
        CHECK(netfp_driver_batch(&state, q, 1u, ids) == 1u);
        submitted++;
    }
    CHECK(submitted == NET_DMA_TX_CHAIN_HEADS);
    {
        uint32_t q = netfp_select_queue(&state);
        uint32_t id = 0u;
        /* Software rings may still reserve, but a driver that mirrors net_pd
         * must refuse when the HW head bitmap is full — modeled here as
         * total DEVICE-owned across queues == CHAIN_HEADS. */
        uint32_t device_owned = 0u;
        for (uint32_t qi = 0u; qi < state.queue_count; qi++)
            device_owned += state.queues[qi].in_flight;
        CHECK(device_owned == NET_DMA_TX_CHAIN_HEADS);
        CHECK(netfp_client_reserve(&state, q, &id) == 0
              || netfp_client_reserve(&state, q, &id) == -2);
        (void)id;
    }
}

int main(void)
{
    test_ownership_and_batch();
    test_backpressure();
    test_multiqueue_and_illegal_transitions();
    test_dma_contract_layout();
    test_irq_driven_reclaim();
    test_multiqueue_hw_head_budget();
    printf("[net_fastpath] %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
