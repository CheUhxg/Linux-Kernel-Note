BINDERFS_DIR = /dev/binderfs
BINDER_DEVICE = binder0

.PHONY: all setup build run clean

all: setup build

setup:
	mkdir -p $(BINDERFS_DIR)
	mount -t binder binder $(BINDERFS_DIR) || true

build:
	gcc server.c -o server
	gcc client.c -o client

run:
	./server &
	./client

clean:
	-umount $(BINDERFS_DIR) 2>/dev/null || true
	-rm -rf $(BINDERFS_DIR) server client