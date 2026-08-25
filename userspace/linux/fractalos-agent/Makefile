# Makefile — fractalos-agent Linux guest agent
#
# Produces: fractalos-agent (native or cross-compiled for AArch64 Linux)
#
# Usage:
#   make                        — native build (for testing on host)
#   make ARCH=aarch64           — cross-compile for AArch64 Linux guest
#   make ARCH=x86_64            — cross-compile for x86-64 Linux guest

ARCH ?= native

ifeq ($(ARCH),aarch64)
    CC = aarch64-linux-gnu-gcc
    LDFLAGS =
else ifeq ($(ARCH),x86_64)
    CC = x86_64-linux-gnu-gcc
    LDFLAGS =
else
    CC = cc
    LDFLAGS =
endif

CFLAGS = -O2 -Wall -Wextra -std=c11

TARGET = fractalos-agent
SRC    = fractalos_agent.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
