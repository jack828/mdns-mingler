CC=gcc
CFLAGS=-pedantic -Wall #-Werror
LDFLAGS=`pkg-config --libs libuv`
EXTRA_LDFLAGS ?=
DEBUGFLAGS=-ggdb -g -O0 -g3
TARGET=mdns

.PHONY: $(TARGET) clean watch debug

$(TARGET):
	$(CC) $(TARGET).c $(CFLAGS) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $(TARGET)

# I used the make to make the make
watch:
	nodemon --exec "make $(TARGET) && ./$(TARGET) || exit 1" --watch $(TARGET).c

debug:
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET).debug $(LDFLAGS) $(DEBUGFLAGS)

clean:
	rm $(TARGET)

