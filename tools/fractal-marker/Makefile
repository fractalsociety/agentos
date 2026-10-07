SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
ROOT := $(abspath ../..)
BUILD ?= $(ROOT)/build/fractal-marker
CPPFLAGS += -D_GNU_SOURCE -I$(ROOT)/platform/include -idirafter $(ROOT)/kernel/agentos-root-task/include
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror
GPT := $(ROOT)/platform/storage/fractal_gpt.c
ENGINE := $(ROOT)/platform/storage/fractal_exchange_cycle.c
CRYPTO := $(ROOT)/libs/pd-support/sha256_mini.c $(ROOT)/libs/pd-support/monocypher.c
HEADERS := $(wildcard $(ROOT)/platform/include/platform/fractal*.h)

.PHONY: all test
all: $(BUILD)/fractal-marker
$(BUILD):
	mkdir -p $@
$(BUILD)/fractal-marker: marker.c $(GPT) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) marker.c $(GPT) -lcrypto -o $@
$(BUILD)/test-marker: test.c marker.c test-key.h $(GPT) $(ENGINE) $(HEADERS) $(CRYPTO) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -include test-key.h -DAGENTOS_FRACTAL_SIGNED_PLAN=1 -DAGENTOS_FRACTAL_PERSISTENT_MARKER=1 test.c $(GPT) $(ENGINE) $(CRYPTO) -lcrypto -o $@
test: all $(BUILD)/test-marker
	$(BUILD)/test-marker
