CC=gcc
CFLAGS=-pedantic -Wall #-Werror
LDFLAGS=`pkg-config --libs libuv`
DEBUGFLAGS=-ggdb -O0
TARGET=mdns

.PHONY: $(TARGET) clean watch debug

$(TARGET):
	$(CC) $(TARGET).c $(CFLAGS) $(LDFLAGS) -o $(TARGET)

# I used the make to make the make
watch:
	nodemon --exec "make $(TARGET) && ./$(TARGET) || exit 1" --watch $(TARGET).c

debug:
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET).debug $(LDFLAGS) $(DEBUGFLAGS)

clean:
	rm $(TARGET)

