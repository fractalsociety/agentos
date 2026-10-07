#include "tco.h"

enum { RELOAD = 0, STATUS1 = 4, STATUS2 = 6, CONTROL = 8, TIMER = 0x12,
       NO_REBOOT = 1, NMI_NOW = 0x100, HALT = 0x800, TICKS = 0x3ff };

bool fractal_tco_select(uint32_t identity, uint32_t base, uint32_t control,
                        uint16_t *port)
{
    if (!port) return false;
    *port = 0;
    /* This profile is specifically Intel 800-series SMBus, TCO version 6. */
    if (identity != UINT32_C(0x7f238086) || !(control & 0x100u) ||
        base == UINT32_MAX || (base & ~UINT32_C(0xffe1)) ||
        (base & 0xffe0u) < 0x100u) return false;
    *port = (uint16_t)(base & 0xffe0u);
    return true;
}

static uint16_t read_reg(const fractal_tco_t *tco, unsigned reg)
{
    return tco->read(tco->context, (uint16_t)(tco->base + reg));
}

static void write_reg(const fractal_tco_t *tco, unsigned reg, uint16_t value)
{
    tco->write(tco->context, (uint16_t)(tco->base + reg), value);
}

static bool valid(const fractal_tco_t *tco)
{
    return tco && tco->read && tco->write && tco->base >= 0x100u &&
           !(tco->base & 31u);
}

bool fractal_tco_stop(const fractal_tco_t *tco)
{
    if (!valid(tco)) return false;
    uint16_t control = read_reg(tco, CONTROL);
    if (control == UINT16_MAX) return false;
    /* Never write back the write-one-to-toggle NMI_NOW bit. */
    write_reg(tco, CONTROL, (control & ~NMI_NOW) | HALT | NO_REBOOT);
    return (read_reg(tco, CONTROL) & (HALT | NO_REBOOT)) == (HALT | NO_REBOOT);
}

bool fractal_tco_arm(const fractal_tco_t *tco, unsigned seconds)
{
    if (!valid(tco) || seconds < 3u || seconds > 614u) return false;
    uint16_t control = read_reg(tco, CONTROL);
    /* Do not take over a watchdog already running for another owner. */
    if (control == UINT16_MAX || !(control & HALT)) return false;
    uint16_t timer = read_reg(tco, TIMER);
    if (timer == UINT16_MAX) return false;
    uint16_t ticks = (uint16_t)(seconds * 10u / 6u);
    write_reg(tco, TIMER, (timer & ~TICKS) | ticks);
    if ((read_reg(tco, TIMER) & TICKS) != ticks) return false;
    write_reg(tco, STATUS1, 8u);
    write_reg(tco, STATUS2, 2u);
    control &= ~(NO_REBOOT | NMI_NOW);
    write_reg(tco, CONTROL, control);
    if ((read_reg(tco, CONTROL) & ~NMI_NOW) != control) return false;
    write_reg(tco, RELOAD, 1u);
    write_reg(tco, CONTROL, control & ~HALT);
    if ((read_reg(tco, CONTROL) & ~NMI_NOW) != (control & ~HALT)) {
        (void)fractal_tco_stop(tco);
        return false;
    }
    return true;
}
