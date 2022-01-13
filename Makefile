CFLAGS=--std=c17 -Wall -pedantic -Isrc/ -ggdb -Wextra -Werror -DDEBUG
BUILDDIR=build
SRCDIR=src
CC=gcc

.PHONY: clean all

all: $(BUILDDIR)/main

build:
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/main: $(BUILDDIR)/mem.o $(BUILDDIR)/util.o $(BUILDDIR)/mem_debug.o $(BUILDDIR)/main.o
	$(CC) -o $@ $^

$(BUILDDIR)/%.o: $(SRCDIR)/%.c build
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf $(BUILDDIR)

