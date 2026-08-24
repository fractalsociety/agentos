#include <stdio.h>
#include <stdlib.h>

int agentos_repo_answer(void);

int main(void)
{
    if (getenv("AGENTOS_REPO_AGENT_TASK") == NULL) {
        puts("ok 1 - managed repository-agent fixture inactive # SKIP");
        return 0;
    }
    if (agentos_repo_answer() == 42) {
        puts("ok 1 - managed repository overlay changed behavior under test");
        return 0;
    }
    puts("not ok 1 - managed repository overlay did not return 42");
    return 1;
}
