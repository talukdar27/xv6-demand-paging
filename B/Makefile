# ==== C-Shark Packet Sniffer Makefile ====

# Compiler and flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

# Output binary
TARGET = cshark

# Source files
SRC = cshark.c
HDR = cshark.h

# ==== Build Rules ====

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Run with sudo (needed for packet capture)
run: $(TARGET)
	sudo ./$(TARGET)

# Clean compiled files
clean:
	rm -f $(TARGET)

# ==== Convenience Aliases ====
rebuild: clean all

.PHONY: all run clean rebuild
