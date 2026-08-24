#include "agent_health.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(agent_capacity_available(8, 0, 8, 0) == 1);
    assert(agent_capacity_available(8, 8, 0, 0) == 0);
    assert(agent_capacity_available(8, 0, 7, 1) == 0);
    assert(agent_capacity_available(8, 0, 9, 0) == 0);
    puts("agent health tests passed");
    return 0;
}
