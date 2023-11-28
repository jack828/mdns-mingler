CC=gcc
CFLAGS= -Wall \
    -Wextra \
    -Werror=pedantic \
    -Wpedantic \
    -Wno-unused-parameter \
    -Wundef \
    -Wshadow \
    -Wformat=2 \
    -Wfloat-equal \
    -Wunreachable-code \
    -std=gnu17
LDFLAGS=`pkg-config --libs libuv`
EXTRA_LDFLAGS ?=
DEBUGFLAGS=-ggdb -g -O0 -g3
TARGET=mdns

.PHONY: $(TARGET) clean watch debug run-valgrind valgrind

$(TARGET):
	$(CC) $(TARGET).c $(CFLAGS) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $(TARGET)

# I used the make to make the make
watch:
	nodemon --signal SIGTERM --exec "make $(TARGET) && ./$(TARGET) || exit 1" --watch $(TARGET).c --watch mdns.h --watch service.h

debug:
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET).debug $(LDFLAGS) $(DEBUGFLAGS)

run-valgrind:
	valgrind -s \
		--tool=memcheck \
		--leak-check=full \
		--track-origins=yes \
		--leak-resolution=high \
		--show-reachable=yes \
		--trace-children=yes ./$(TARGET).debug

valgrind: debug run-valgrind

clean:
	rm $(TARGET)

