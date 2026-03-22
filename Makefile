CC      := gcc
CFLAGS  := -Wall -Wextra -O2 $(shell pkg-config --cflags fuse3)
LDFLAGS := $(shell pkg-config --libs fuse3) -lssl -lcrypto

SRC     := src/obfuse.c src/crypto.c
OBJ     := $(SRC:.c=.o)
TARGET  := obfuse

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
