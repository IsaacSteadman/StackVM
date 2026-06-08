/*
 * stackvm_mmio.h - Phase-2 MMIO device map for StackVM kernels.
 *
 * The Python reference emulator dispatches accesses in these physical windows
 * to host-backed devices instead of RAM.  IRQ lines are routed through the MMIO
 * interrupt controller and delivered as architectural interrupt vectors.
 */

#ifndef STACKVM_MMIO_H
#define STACKVM_MMIO_H

#include "stackvm.h"

#define SVM_MMIO_BASE 0xFFFF0000ULL
#define SVM_MMIO_WINDOW_SIZE 0x1000ULL

#define SVM_MMIO_UART0_BASE (SVM_MMIO_BASE + 0x0000ULL)
#define SVM_MMIO_IC_BASE (SVM_MMIO_BASE + 0x1000ULL)
#define SVM_MMIO_RTC_BASE (SVM_MMIO_BASE + 0x2000ULL)
#define SVM_MMIO_VIRTIO_BLK0_BASE (SVM_MMIO_BASE + 0x3000ULL)
#define SVM_MMIO_VIRTIO_NET0_BASE (SVM_MMIO_BASE + 0x4000ULL)

#define SVM_IRQ_UART0 1u
#define SVM_IRQ_VIRTIO_BLK0 2u
#define SVM_IRQ_RTC 3u
#define SVM_IRQ_VIRTIO_NET0 4u

/* UART registers. */
#define SVM_UART_DATA 0x00u
#define SVM_UART_STATUS 0x08u
#define SVM_UART_IRQ_ENABLE 0x10u
#define SVM_UART_IRQ_STATUS 0x18u
#define SVM_UART_IRQ_ACK 0x20u

#define SVM_UART_STATUS_RX_READY (1u << 0)
#define SVM_UART_STATUS_TX_READY (1u << 1)
#define SVM_UART_IRQ_RX (1u << 0)

/* Interrupt-controller registers. */
#define SVM_IC_PENDING 0x00u
#define SVM_IC_ENABLE 0x08u
#define SVM_IC_CLAIM 0x10u
#define SVM_IC_EOI 0x18u
#define SVM_IC_ROUTE_BASE 0x100u
#define SVM_IC_PRIORITY_BASE 0x300u
#define SVM_IC_NO_PENDING (~0ULL)

/* RTC registers. */
#define SVM_RTC_NOW_NS 0x00u
#define SVM_RTC_NOW_SEC 0x08u

/* Compact virtio-MMIO transport registers. */
#define SVM_VIRTIO_MAGIC 0x00u
#define SVM_VIRTIO_VERSION 0x04u
#define SVM_VIRTIO_DEVICE_ID 0x08u
#define SVM_VIRTIO_STATUS 0x0Cu
#define SVM_VIRTIO_QUEUE_DESC 0x10u
#define SVM_VIRTIO_QUEUE_AVAIL 0x18u
#define SVM_VIRTIO_QUEUE_USED 0x20u
#define SVM_VIRTIO_QUEUE_NUM 0x28u
#define SVM_VIRTIO_QUEUE_NOTIFY 0x30u
#define SVM_VIRTIO_INTERRUPT_STATUS 0x38u
#define SVM_VIRTIO_INTERRUPT_ACK 0x40u
#define SVM_VIRTIO_DRIVER_FEATURES 0x48u
#define SVM_VIRTIO_DEVICE_FEATURES 0x50u
#define SVM_VIRTIO_QUEUE_SEL 0x58u

#define SVM_VIRTIO_MAGIC_VALUE 0x74726976u
#define SVM_VIRTIO_VERSION_VALUE 2u
#define SVM_VIRTIO_DEVICE_NET 1u
#define SVM_VIRTIO_DEVICE_BLOCK 2u

#define SVM_VIRTQ_DESC_SIZE 16u
#define SVM_VIRTQ_DESC_F_NEXT 1u
#define SVM_VIRTQ_DESC_F_WRITE 2u

#define SVM_VIRTIO_BLK_SECTOR_SIZE 512u
#define SVM_VIRTIO_BLK_T_IN 0u
#define SVM_VIRTIO_BLK_T_OUT 1u
#define SVM_VIRTIO_BLK_S_OK 0u
#define SVM_VIRTIO_BLK_S_IOERR 1u

#define SVM_VIRTIO_NET_HDR_SIZE 10u

struct SvmVirtqDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct SvmVirtioBlkReq {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
};

#endif /* STACKVM_MMIO_H */
