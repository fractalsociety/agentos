/* Bounded pre-OS recovery for the HM870 TCO v6 watchdog. */
#ifndef FRACTAL_TCO_H
#define FRACTAL_TCO_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    void *context;
    uint16_t (*read)(void *, uint16_t);
    void (*write)(void *, uint16_t, uint16_t);
    uint16_t base;
} fractal_tco_t;

/* Discovery does not enable PCI decode or change a firmware-assigned base. */
bool fractal_tco_select(uint32_t identity, uint32_t base, uint32_t control,
                        uint16_t *port);
bool fractal_tco_arm(const fractal_tco_t *tco, unsigned seconds);
bool fractal_tco_stop(const fractal_tco_t *tco);
#endif
