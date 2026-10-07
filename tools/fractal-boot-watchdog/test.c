#include "tco.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint16_t r[16];
    unsigned writes, reloads;
    bool timer_locked, reboot_locked, halt_locked;
} model_t;

static uint16_t read_port(void *context, uint16_t port)
{
    model_t *m = context;
    assert(port >= 0x8e00 && port < 0x8e20 && !(port & 1));
    return m->r[(port - 0x8e00)/2];
}

static void write_port(void *context, uint16_t port, uint16_t value)
{
    model_t *m = context;
    unsigned reg = port - 0x8e00;
    assert(port >= 0x8e00 && port < 0x8e20 && !(port & 1));
    ++m->writes;
    if (reg == 8) {
        assert(!(value & 0x100)); /* NMI must never be requested. */
        if (m->reboot_locked) value |= 1;
        if (m->halt_locked) value |= 0x800;
        m->r[4] = value;
    } else if (reg == 4 || reg == 6) {
        m->r[reg/2] &= ~value; /* Write-one-to-clear status. */
    } else if (reg == 0) {
        assert(value == 1);
        m->r[0] = m->r[9] & 0x3ff;
        ++m->reloads;
    } else if (reg == 0x12) {
        if (!m->timer_locked) m->r[9] = value;
    } else assert(0);
}

static void reset(model_t *m)
{
    memset(m, 0, sizeof(*m));
    m->r[4] = 0x2801; /* Halted, reset inhibited, unrelated bit set. */
    m->r[9] = 0x8000;
    m->r[2] = 0x18;
    m->r[3] = 0x12;
}

int main(void)
{
    uint16_t port;
    assert(fractal_tco_select(0x7f238086, 0x8e01, 0x100, &port) && port == 0x8e00);
    assert(!fractal_tco_select(0x12348086, 0x8e01, 0x100, &port) && !port);
    assert(!fractal_tco_select(0x7f238086, 0x8e01, 0, &port));
    assert(!fractal_tco_select(0x7f238086, 0x10008e01, 0x100, &port));
    assert(!fractal_tco_select(0x7f238086, 0x8e03, 0x100, &port));
    assert(!fractal_tco_select(0x7f238086, 1, 0x100, &port));
    model_t m;
    fractal_tco_t t = {.context=&m, .read=read_port, .write=write_port, .base=0x8e00};
    reset(&m);
    assert(fractal_tco_arm(&t, 120));
    assert(m.r[9] == 0x80c8 && m.r[0] == 200 && m.reloads == 1);
    assert(m.r[4] == 0x2000 && m.r[2] == 0x10 && m.r[3] == 0x10);
    unsigned writes = m.writes;
    assert(!fractal_tco_arm(&t, 120) && m.writes == writes);
    assert(fractal_tco_stop(&t) && m.r[4] == 0x2801);
    for (unsigned seconds = 3; seconds <= 614; ++seconds) {
        reset(&m);
        assert(fractal_tco_arm(&t, seconds));
        assert(m.r[0] == seconds * 10 / 6);
    }
    reset(&m);
    assert(!fractal_tco_arm(&t, 2) && !fractal_tco_arm(&t, 615) && !m.writes);
    m.timer_locked = true;
    assert(!fractal_tco_arm(&t, 120) && !m.reloads && m.r[4] == 0x2801);
    reset(&m); m.reboot_locked = true;
    assert(!fractal_tco_arm(&t, 120) && !m.reloads && (m.r[4] & 0x800));
    reset(&m); m.halt_locked = true;
    assert(!fractal_tco_arm(&t, 120) && (m.r[4] & 0x801) == 0x801);
    reset(&m); m.r[4] |= 0x100;
    assert(fractal_tco_arm(&t, 120) && fractal_tco_stop(&t));
    reset(&m); m.r[4] = UINT16_MAX;
    assert(!fractal_tco_arm(&t, 120) && !fractal_tco_stop(&t) && !m.writes);
    assert(!fractal_tco_arm(NULL, 120));
    puts("PASS: TCO identity, timeout, reset enable, halt, status, reserved bits and hardware refusal");
}
