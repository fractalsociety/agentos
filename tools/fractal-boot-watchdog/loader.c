/* Firmware companion, not a seL4 PD. No namespace access or boot-variable
 * changes. Arm real hardware before entering the experimental boot path. */
#include <efi.h>
#include <efilib.h>
#include "tco.h"

static uint16_t in16(void *context, uint16_t port)
{
    (void)context;
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void out16(void *context, uint16_t port, uint16_t value)
{
    (void)context;
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static uint32_t pci_read(unsigned offset)
{
    uint32_t saved, value, select = UINT32_C(0x8080fc00) | offset;
    __asm__ volatile("inl %1, %0" : "=a"(saved) : "Nd"((uint16_t)0xcf8));
    __asm__ volatile("outl %0, %1" : : "a"(select), "Nd"((uint16_t)0xcf8));
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"((uint16_t)0xcfc));
    __asm__ volatile("outl %0, %1" : : "a"(saved), "Nd"((uint16_t)0xcf8));
    return value;
}

static void cold_reset(void)
{
    uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_DEVICE_ERROR, 0, NULL);
    for (;;) __asm__ volatile("pause");
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table)
{
    InitializeLib(image, table);
    fractal_tco_t tco = {.read = in16, .write = out16};
    if (!fractal_tco_select(pci_read(0), pci_read(0x50), pci_read(0x54), &tco.base)) {
        Print(L"Fractal: supported hardware watchdog unavailable; boot refused.\r\n");
        return EFI_UNSUPPORTED;
    }
    EFI_LOADED_IMAGE *loaded = NULL;
    EFI_STATUS status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
                                          &LoadedImageProtocol, (VOID **)&loaded);
    if (EFI_ERROR(status) || !loaded) return EFI_LOAD_ERROR;
    EFI_DEVICE_PATH *path = FileDevicePath(loaded->DeviceHandle,
                                           L"\\EFI\\FractalWatchdog\\LIMINE.EFI");
    if (!path) return EFI_OUT_OF_RESOURCES;
    EFI_HANDLE child = NULL;
    status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, image, path, NULL, 0, &child);
    FreePool(path);
    if (EFI_ERROR(status)) return status;
    uint16_t initial_control = in16(NULL, (uint16_t)(tco.base + 8u));
    if (initial_control == UINT16_MAX || !(initial_control & 0x800u)) {
        Print(L"Fractal: watchdog is inaccessible or already owned; boot refused.\r\n");
        uefi_call_wrapper(BS->UnloadImage, 1, child);
        return EFI_DEVICE_ERROR;
    }
    if (!fractal_tco_arm(&tco, 120u)) {
        Print(L"Fractal: watchdog did not arm; boot refused.\r\n");
        /* A failed final readback may still have started the countdown. */
        if (!fractal_tco_stop(&tco)) cold_reset();
        uefi_call_wrapper(BS->UnloadImage, 1, child);
        return EFI_DEVICE_ERROR;
    }
    Print(L"Fractal: hardware recovery watchdog armed (120 seconds).\r\n");
    status = uefi_call_wrapper(BS->StartImage, 3, child, NULL, NULL);
    /* Boot services still exist if StartImage returns. Do not leave an
     * unexpected reset timer running while firmware starts the normal OS. */
    if (!fractal_tco_stop(&tco)) {
        Print(L"Fractal: watchdog could not stop; requesting cold reset.\r\n");
        cold_reset();
    }
    uefi_call_wrapper(BS->UnloadImage, 1, child);
    return status;
}
