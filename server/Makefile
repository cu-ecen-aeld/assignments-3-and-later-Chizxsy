CC ?= $(CROSS_COMPILE)gcc

CFLAGS ?= -Wall -Werror -g

LDFLAGS ?= -lpthread -lrt

TARGET ?= aesdsocket
SOURCE ?= aesdsocket.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)


clean:
	rm -f $(TARGET)

.PHONY: all clean
