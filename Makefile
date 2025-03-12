CC=gcc
CFLAGS=-Werror -Wall
LDLIBS=
OUTPUT=reverse_proxy

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): main.o
	cppcheck --enable=performance unusedFunction --error-exitcode=1 *c
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

clean:
	rm -rf *.o $(OUTPUT)

