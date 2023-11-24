CC=gcc
CFLAGS=-pedantic -Wall #-Werror
LDFLAGS=`pkg-config --libs libuv`
DEBUGFLAGS=-ggdb -O0
TARGET=mdns

.PHONY: $(TARGET) clean debug

$(TARGET):
	$(CC) $(TARGET).c $(CFLAGS) $(LDFLAGS) -o $(TARGET)

debug:
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET).debug $(LDFLAGS) $(DEBUGFLAGS)

clean:
	rm $(TARGET)

