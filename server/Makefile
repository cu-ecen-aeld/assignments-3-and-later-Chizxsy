CC ?= $(CROSS_COMPILE)gcc

CFLAGS ?= -Wall -Werror -g -DUSE_AESD_CHAR_DEVICE=1

LDFLAGS ?= -lpthread -lrt

TARGET ?= aesdsocket
SOURCE ?= aesdsocket.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
