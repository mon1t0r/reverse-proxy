CC=gcc
CFLAGS=-Werror -Wall
LDLIBS=
OUTPUT=reverse_proxy

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): main.o nat_table.o checksum.o network_layer.o transport_layer.o
	cppcheck --enable=performance unusedFunction --error-exitcode=1 --check-level=exhaustive *c
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

nat_table.o: nat_table.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

checksum.o: checksum.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

network_layer.o: network_layer.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

transport_layer.o: transport_layer.c
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

clean:
	rm -rf *.o $(OUTPUT)

