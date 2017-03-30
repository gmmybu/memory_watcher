#pragma once
#include <stdint.h>
#include "callstack.h"

struct memory_block
{
    void* _start_ptr;

    uint32_t _length;

    SafeCallStack _call_stack;

    DWORD _free_time;  /// to check double free

    memory_block* _next;
};

class memory_watcher
{
public:
    memory_watcher();

    void on_memory_alloc(void* start_ptr, uint32_t length);

    void on_memory_realloc(void* old_ptr, void* new_ptr, uint32_t new_length);

    void on_memory_free(void* start_ptr);

    void on_shutdown();
private:
    uint32_t find_block(void* start_ptr); /// 查找所在的slot下标

    memory_block* _block_slots[1024 * 1024]; /// 一个孔放置4k内容
private:
    void do_delay_free(bool force = false);

    void delay_free_one_block();

    memory_block* check_is_delay_free(void* ptr);

    bool validate_block(memory_block* block);

    memory_block* _delay_free_head;

    memory_block* _delay_free_tail;
private:
    void block_pool_init();

    memory_block* block_pool_alloc();

    void block_pool_free(memory_block*);

    memory_block* _block_header; /// 内存块分配的头部

    memory_block _block_pool[1024 * 100]; /// 内存同时使用最大块数
private:
    void output_memory_info(bool force = false);

    DWORD _last_output_time;

    uint32_t _delay_free_block; /// 统计信息

    uint32_t _delay_free_memory_size;

    uint32_t _current_block_count;
    
    uint32_t _current_memory_size;

    uint32_t _max_block_count;

    uint32_t _max_memory_size;
private:
    void report_heap_corruption(CallStack* call_stack);

    void report_heap_leak();
private:
    memory_watcher(const memory_watcher&);
    memory_watcher& operator=(const memory_watcher&);
};
