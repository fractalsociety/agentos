#include "agent_health.h"

int agent_capacity_available(unsigned total, unsigned busy,
                             unsigned idle, unsigned faulted)
{
    (void)total;
    (void)busy;
    (void)idle;
    (void)faulted;
    return 0;
}
