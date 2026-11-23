# H01 "Zancudo Deadbolt" -- organizer build (run inside WSL / Linux x86-64).
# Produces a stripped position-independent ELF named `zancudo_gate`.
CC     ?= gcc
CFLAGS ?= -O2 -Wall

zancudo_gate: zancudo_gate.c
	$(CC) $(CFLAGS) -o $@ $<
	strip -s $@

clean:
	rm -f zancudo_gate

.PHONY: clean
