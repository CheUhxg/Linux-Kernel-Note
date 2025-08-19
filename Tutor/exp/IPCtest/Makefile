CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lrt -lpthread
TEST_RUNS = 10  # 每个测试运行次数

TARGETS = pipe_anonymous \
          pipe_named_reader pipe_named_writer \
          shared_memory \
          msg_queue \
          semaphore_sync

all: $(TARGETS)

# 编译规则
pipe_anonymous: pipe_anonymous.c
	$(CC) $(CFLAGS) $^ -o $@

pipe_named_reader: pipe_named_reader.c
	$(CC) $(CFLAGS) $^ -o $@

pipe_named_writer: pipe_named_writer.c
	$(CC) $(CFLAGS) $^ -o $@

shared_memory: shared_memory.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

msg_queue: msg_queue.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

semaphore_sync: semaphore_sync.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# 测试流程
test: all
	@echo "\n=== 开始测试 ==="
	@$(MAKE) -s test_pipe_anon
	@$(MAKE) -s test_pipe_named
	@$(MAKE) -s test_sharedmem
	@$(MAKE) -s test_msgqueue
	@$(MAKE) -s test_semaphore
	@echo "\n=== 测试完成 ==="

test_pipe_anon: pipe_anonymous
	@echo "\n[测试匿名管道]"
	@for i in $$(seq 1 $(TEST_RUNS)); do \
		echo ">> 第 $$i 次运行"; \
		./$<; \
	done

test_pipe_named: pipe_named_reader pipe_named_writer
	@echo "\n[测试有名管道]"
	@-mkfifo /tmp/test_fifo 2>/dev/null
	@for i in $$(seq 1 $(TEST_RUNS)); do \
		echo ">> 第 $$i 次运行"; \
		(./pipe_named_reader &); \
		timeout 2s ./pipe_named_writer; \
	done

test_sharedmem: shared_memory
	@echo "\n[测试共享内存]"
	@for i in $$(seq 1 $(TEST_RUNS)); do \
		echo ">> 第 $$i 次运行"; \
		./$<; \
	done

test_msgqueue: msg_queue
	@echo "\n[测试消息队列]"
	@for i in $$(seq 1 $(TEST_RUNS)); do \
		echo ">> 第 $$i 次运行"; \
		./$<; \
	done

test_semaphore: semaphore_sync
	@echo "\n[测试信号量]"
	@for i in $$(seq 1 $(TEST_RUNS)); do \
		echo ">> 第 $$i 次运行"; \
		./$<; \
	done

clean:
	@rm -f $(TARGETS) \
        /tmp/test_fifo \
        /dev/mqueue/test_mq \
        /dev/shm/*test_*
	@echo "已清理生成文件"