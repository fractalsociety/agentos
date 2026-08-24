.PHONY: test clean

test: test_agent_health
	./test_agent_health

test_agent_health: agent_health.c agent_health.h test_agent_health.c
	$(CC) -std=c11 -Wall -Wextra -Werror agent_health.c test_agent_health.c -o $@

clean:
	rm -f test_agent_health
