
all: mkdirs cdump ptrace

SRCS:=$(wildcard *.c)
OBJS:=$(patsubst %.c, %.o, $(SRCS))

mkdirs:
	mkdir -p results/
results/%.o: %.c
	gcc -g -O0 -c $(CFLAGS) $< -o $@

ptrace: results/elf_utils.o results/ptrace.o
	gcc $^ -o $@

cdump: results/cdump.o
	gcc $^ -o $@ -O2 #-fno-omit-frame-pointer

clean:
	rm -rf cdump ptrace results/*.o results/

