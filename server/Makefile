CFLAGS := -Wall -Werror -g

TARGET := aesdsocket
SOURCE := aesdsocket.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)


clean:
	rm -f $(TARGET)

.PHONY: all clean
