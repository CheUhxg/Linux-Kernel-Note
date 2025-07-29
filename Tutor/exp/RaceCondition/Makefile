CC = gcc
CFLAGS = -Wall -g -O0
LDFLAGS = -lpthread
TARGET = test

all: $(TARGET)

$(TARGET): test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: $(TARGET)
	@echo "========= 运行测试程序 ========="
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean