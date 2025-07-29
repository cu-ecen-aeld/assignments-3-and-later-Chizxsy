
TARGET = writer

# Use the CC and CFLAGS variables passed in by Buildroot's environment
all:
	$(CC) $(CFLAGS) -o $(TARGET) writer.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
