CC ?= gcc
CLANG ?= clang

CFLAGS ?= -O2 -std=gnu11 -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= -lbpf -lelf -lz

DAEMON_SRCS := \
	daemon/main.c \
	daemon/bpf_runtime.c \
	daemon/classifier.c \
	daemon/detector.c \
	daemon/controller.c \
	daemon/util.c

DAEMON_BIN := build/adaptive-latencyd
BPF_OBJ := build/flowmon.bpf.o

.PHONY: all daemon bpf clean

all: daemon bpf

daemon: $(DAEMON_BIN)

bpf: $(BPF_OBJ)

build:
	mkdir -p build

$(DAEMON_BIN): $(DAEMON_SRCS) | build
	$(CC) $(CFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS) $(LDLIBS)

$(BPF_OBJ): bpf/flowmon.bpf.c bpf/flow_stats.h | build
	$(CLANG) $(BPF_CFLAGS) -c bpf/flowmon.bpf.c -o $@

clean:
	rm -rf build
