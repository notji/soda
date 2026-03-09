CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Os -static -s -ffunction-sections -fdata-sections
LDLFLAGS = -Wl,--gc-sections
LIBS = -lws2_32 -liphlpapi
TARGET = build/soda.exe
SRC = $(wildcard src/*.c) 

.PHONY: all clean

all: build $(TARGET)
	@echo "Build complete: $(TARGET)"

build:
	@mkdir -p build

$(TARGET): $(SRC)
	@echo "Compiling $(SRC)..."
	@$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -rf build
	@echo "Cleaned."
