# Build for sec_uart
#
# Requires Mbed TLS (libmbedcrypto). If it is not installed system-wide,
# point MBEDTLS_DIR at an install prefix, e.g.:
#   make MBEDTLS_DIR=$HOME/mbedtls/install

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS  += -lmbedcrypto

ifdef MBEDTLS_DIR
CPPFLAGS += -I$(MBEDTLS_DIR)/include
LDFLAGS  += -L$(MBEDTLS_DIR)/lib -Wl,-rpath,$(MBEDTLS_DIR)/lib
endif

LIB_OBJS := uart_frame.o uart_dfu.o uart_simple.o
TARGETS  := example dfu_example simple_example
OBJS     := $(LIB_OBJS) $(TARGETS:=.o)
DEPS     := $(OBJS:.o=.d)

.PHONY: all clean run test

all: $(TARGETS)

example: example.o $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

dfu_example: dfu_example.o $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

simple_example: simple_example.o $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

run: example
	./example

test: $(TARGETS)
	./example
	./dfu_example
	./simple_example

clean:
	rm -f $(TARGETS) $(OBJS) $(DEPS)

-include $(DEPS)
