#!/usr/bin/env python3
"""Static ownership proof for the native VirtIO NIC topology."""

import pathlib


def block(text, start, end):
    return text[text.index(start):text.index(end, text.index(start))]


def main():
    repo = pathlib.Path(__file__).resolve().parents[1]
    desc = (repo / "kernel/fractalos-root-task/src/system_desc_aarch64.c").read_text()
    root = (repo / "kernel/fractalos-root-task/src/main.c").read_text()
    driver = (repo / "services/net-service/net_pd.c").read_text()
    stack = (repo / "services/net-server/net_server.c").read_text()
    wireguard = (repo / "kernel/fractalos-root-task/src/wg_net.c").read_text()

    net_pd = block(desc, '.name           = "net_pd"', '/* pd[13]')
    net_server = block(desc, '.name           = "net_server"', '/* Native inference')
    vmm = block(desc, '/* pd[15] — guest VMM', '#if defined(FRACTALOS_GUEST_BOTH)')
    assert '.irq_number = 48u' in net_pd
    assert 'SVC_ID_NET_PD' in net_server and 'PD_CNODE_SLOT_NET_PD_EP' in net_server
    assert 'NET_PD_RIGHT_FASTPATH' in net_server
    assert '.irq_number = 48u' not in vmm
    assert 'name_eq(pd->name, "net_pd")' in root
    assert 'name_eq(pd->name, "linux_vmm") || name_eq(pd->name, "freebsd_vmm")' not in block(
        root, 'net_pd is the sole writable owner', 'if (name_eq(pd->name, "freebsd_vmm"))')
    assert 'net_mmio_vaddr = 0u' in stack
    assert 'NET_PD_MMIO_VA' in root and 'net_pd_mmio_vaddr = (uintptr_t)0x10010000u' in driver
    assert 'seL4_IRQHandler_Ack' in driver and 'handle_net_irq' in driver
    assert 'NET_DMA_STARTUP_VA' in root and 'dma_base_pa' in driver
    assert 'VIRTIO_MMIO_QUEUE_DESC_LOW' in driver
    assert 'VIRTIO_MMIO_QUEUE_READY' in driver
    assert 'VIRTIO_STATUS_DRIVER_OK' in driver
    assert 'netfp_init(fastpath, 1u)' in driver
    assert 'badge_has_fastpath' in driver and 'return SEL4_ERR_PERM' in driver
    assert 'MSG_NET_FASTPATH_SEND' in stack and 'sel4_client_call(g_net_pd_ep' in stack
    assert 'g_netif.linkoutput(&g_netif, p)' not in block(
        stack, 'Handler: OP_NET_VNIC_SEND', 'Handler: OP_NET_VNIC_RECV')
    wg = desc[desc.index('.name           = "wg_net"'):]
    assert 'SVC_ID_NET_SERVER' in wg and 'PD_CNODE_SLOT_NET_SERVER_EP' in wg
    assert 'SVC_ID_MODELSVC' not in wg
    assert 'SVC_ID_TOOLSVC' not in wg
    assert 'SVC_ID_AGENTFS' not in wg
    assert 'SVC_ID_EXEC_SERVER' not in wg
    assert 'g_net_ep = (seL4_CPtr)PD_CNODE_SLOT_NET_SERVER_EP' in wireguard
    assert 'lreq.opcode = (uint32_t)OP_NS_LOOKUP' not in wireguard
    assert 'name_eq(pd->name, "wg_net") || name_eq(pd->name, "test_runner")' in root
    print('[PASS] net_pd is the sole IRQ/MMIO owner; net_server is a client')
    print('[PASS] wg_net boots with an explicit NetServer capability only')


if __name__ == '__main__':
    main()
