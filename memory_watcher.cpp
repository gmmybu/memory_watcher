#include "dbghelpapi.h"
#include <crtdbg.h>
#include "memory_watcher.h"
#include "mhook-lib/mhook.h"

#define GUARD_NUM 0xcc

typedef void* (*malloc_t)(size_t size);
typedef void* (*calloc_t)(size_t n, size_t size);
typedef void* (*realloc_t)(void* ptr, size_t size);
typedef void  (*free_t)(void* ptr);

malloc_t malloc_func;

calloc_t calloc_func;

realloc_t realloc_func;

free_t free_func;

struct hook_state
{
    DWORD  _storage_index;

    bool   _initializing;

    bool   _enabled;

    CRITICAL_SECTION _mutex;
};

hook_state _hook_state;

#define MAXMODULENAME 256

#define currentprocess GetCurrentProcess()
#define currentthread  GetCurrentThread()

BOOL WINAPI attach_to_module(PCWSTR modulepath, DWORD64 modulebase, ULONG modulesize, PVOID)
{
    size_t              count;
    WCHAR               extension[_MAX_EXT];
    WCHAR               filename[_MAX_FNAME];
    IMAGEHLP_MODULE64   moduleimageinfo;
    WCHAR               modulename[MAXMODULENAME + 1];
    CHAR                modulepatha[MAX_PATH];
    BOOL                refresh = FALSE;

    _wsplitpath_s(modulepath, NULL, 0, NULL, 0, filename, _MAX_FNAME, extension, _MAX_EXT);
    wcsncpy_s(modulename, MAXMODULENAME + 1, filename, _TRUNCATE);
    wcsncat_s(modulename, MAXMODULENAME + 1, extension, _TRUNCATE);
    _wcslwr_s(modulename, MAXMODULENAME + 1);

    moduleimageinfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    wcstombs_s(&count, modulepatha, MAX_PATH, modulepath, _TRUNCATE);
    if ((pSymGetModuleInfoW64(currentprocess, modulebase, &moduleimageinfo) == TRUE) ||
        ((pSymLoadModule64(currentprocess, NULL, modulepatha, NULL, modulebase, modulesize) == modulebase) &&
        (pSymGetModuleInfoW64(currentprocess, modulebase, &moduleimageinfo) == TRUE)))
    {
    }

    return TRUE;
}

memory_watcher* _the_manager = nullptr;

void* hook_malloc(size_t size);
void* hook_calloc(size_t n, size_t size);
void* hook_realloc(void* ptr, size_t size);
void  hook_free(void* ptr);

bool hook_state_initialize()
{
    _hook_state._enabled = false;
    _hook_state._storage_index = TLS_OUT_OF_INDEXES;
    _the_manager = new memory_watcher;

    if (!link_debughelp_library()) {
        OutputDebugStringA("link_debughelp_library\n");
        return false;
    }

    _hook_state._storage_index = TlsAlloc();
    if (_hook_state._storage_index == TLS_OUT_OF_INDEXES) {
        OutputDebugStringA("invalid storage index\n");
        return false;
    }

    HMODULE module = LoadLibrary(L"msvcr110.dll");
    malloc_func = (malloc_t)GetProcAddress(module, "malloc");
    calloc_func = (calloc_t)GetProcAddress(module, "calloc");
    realloc_func = (realloc_t)GetProcAddress(module, "realloc");
    free_func = (free_t)GetProcAddress(module, "free");
    if (malloc_func == nullptr || free_func == nullptr) {
        OutputDebugStringA("GetProcAddress\n");
        return false;
    }

    InitializeCriticalSectionAndSpinCount(&_hook_state._mutex, 100);

    _hook_state._initializing = true;
    Mhook_SetHook((PVOID*)&free_func, hook_free);
    Mhook_SetHook((PVOID*)&realloc_func, hook_realloc);
    Mhook_SetHook((PVOID*)&malloc_func, hook_malloc);
    Mhook_SetHook((PVOID*)&calloc_func, hook_calloc);
    _hook_state._initializing = false;
    _hook_state._enabled = true;
    return true;
}

void hook_state_uninitialize()
{
    if (_hook_state._enabled) {
        _hook_state._enabled = false;
        Mhook_Unhook((PVOID*)&malloc_func);
        Mhook_Unhook((PVOID*)&free_func);

        DeleteCriticalSection(&_hook_state._mutex);
        _the_manager->on_shutdown();
    }

    if (_hook_state._storage_index != TLS_OUT_OF_INDEXES) {
        TlsFree(_hook_state._storage_index);
        _hook_state._storage_index = TLS_OUT_OF_INDEXES;
    }

    delete _the_manager;
    _the_manager = nullptr;
}

void hook_state_prepare_stack_info()
{
    pSymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    wchar_t program[MAX_PATH * 3] = { };
    GetModuleFileName(NULL, program, MAX_PATH);

    int prev = -1;
    for (int i = 0; i < MAX_PATH && program[i]; i++) {
        if (program[i] == L'\\') {
            prev = i;
        }
    }

    if (prev != -1) {
        program[prev] = L'\0';
    }

    wcscpy(program + wcslen(program), L";D:\Microsoft Visual Studio 11.0\VC\lib");

    if (!pSymInitializeW(GetCurrentProcess(), program, FALSE)) {
        OutputDebugStringA("SymInitialize\n");
    }

    pEnumerateLoadedModulesW64(GetCurrentProcess(), attach_to_module, NULL);
}

class auto_heap_guard
{
public:
    auto_heap_guard(SIZE_T* frame_pointer) : _will_reset(false)
    {
        EnterCriticalSection(&_hook_state._mutex);
        TlsSetValue(_hook_state._storage_index, frame_pointer);
    }

    ~auto_heap_guard()
    {
        TlsSetValue(_hook_state._storage_index, nullptr);
        LeaveCriticalSection(&_hook_state._mutex);
    }
private:
    bool _will_reset;
};

#define BPREG Ebp
#define FRAMEPOINTER(fp) __asm mov fp, BPREG // Copies the current frame pointer to the supplied variable.

void* hook_malloc(size_t size)
{
    if (_hook_state._initializing)
        return malloc_func(size);

    if (size == 0) { size = 4; }

    uint8_t* data = (uint8_t*)malloc_func(size + 16);
    if (data == nullptr)
        return nullptr;

    for (size_t i = 0; i < 16; i++) {
        data[size + i] = GUARD_NUM; /// 检查越界写，向前越界的比较少见，且暂时无法实现
    }

    SIZE_T* frame_pointer = NULL;
    FRAMEPOINTER(frame_pointer);

    auto_heap_guard guard(frame_pointer);
    if (_hook_state._enabled) {
        _the_manager->on_memory_alloc(data, size);
    }

    return data;
}

void* hook_calloc(size_t n, size_t size)
{
    if (_hook_state._initializing)
        return calloc_func(n, size);

    size *= n;

    uint8_t* data = (uint8_t*)malloc_func(size + 16);
    if (data == nullptr)
        return nullptr;

    memset(data, size, 0);

    for (size_t i = 0; i < 16; i++) {
        data[size + i] = GUARD_NUM; /// 检查越界写，向前越界的比较少见，且暂时无法实现
    }

    SIZE_T* frame_pointer = NULL;
    FRAMEPOINTER(frame_pointer);

    auto_heap_guard guard(frame_pointer);
    if (_hook_state._enabled) {
        _the_manager->on_memory_alloc(data, size);
    }

    return data;
}

void* hook_realloc(void* ptr, size_t size)
{
    if (_hook_state._initializing)
        return realloc_func(ptr, size);

    if (ptr == nullptr)
        return malloc(size);

    if (size == 0) {
        free(ptr);
        return nullptr;
    }

    uint8_t* data = (uint8_t*)realloc_func(ptr, size + 16);
    if (data == nullptr)
        return nullptr;

    for (size_t i = 0; i < 16; i++) {
        data[size + i] = GUARD_NUM; /// 检查越界写，向前越界的比较少见，且暂时无法实现
    }

    SIZE_T* frame_pointer = NULL;
    FRAMEPOINTER(frame_pointer);

    auto_heap_guard guard(nullptr);
    if (_hook_state._enabled) {
        _the_manager->on_memory_realloc(ptr, data, size);
    }

    return data;
}

void hook_free(void* ptr)
{
    if (_hook_state._initializing)
        return free_func(ptr);

    if (ptr == nullptr)
        return;

    {
        auto_heap_guard guard(nullptr);
        if (_hook_state._enabled) {
            return _the_manager->on_memory_free(ptr);
        }
    }

    free_func(ptr);
}

memory_watcher::memory_watcher()
{
    memset(_block_slots, 0, sizeof(_block_slots));
    _delay_free_head = nullptr;
    _delay_free_tail = nullptr;

    _not_freed_count = 0;

    _delay_free_block = 0;
    _delay_free_memory_size = 0;

    _current_block_count = 0;
    _current_memory_size = 0;
    
    _max_block_count = 0;
    _max_memory_size = 0;
    _last_output_time = GetTickCount();

    block_pool_init();
}

void memory_watcher::block_pool_init()
{
    for (uint32_t i = 0; i < 1024 * 100 - 1; i++) {
        _block_pool[i]._next = _block_pool + i + 1;
    }

    _block_pool[1024 * 100 - 1]._next = nullptr;
    
    _block_header = _block_pool;
}

memory_block* memory_watcher::block_pool_alloc()
{
    if (_block_header != nullptr) {
        auto block = _block_header;
        _block_header = block->_next;
        return block;
    }

    /// 尝试释放掉delay_free里面的元素
    do_delay_free(true);

    if (_block_header != nullptr) {
        auto block = _block_header;
        _block_header = block->_next;
        return block;
    }

    /// 可能可以等其他地方释放
    return nullptr;
}

void memory_watcher::block_pool_free(memory_block* block)
{
    block->_next = _block_header;
    _block_header = block;
}

void memory_watcher::do_delay_free(bool force)
{
    if (force) { delay_free_one_block(); }

    if (_delay_free_head == nullptr) return;

    DWORD tick = GetTickCount();
    while (_delay_free_head != nullptr) {
        auto block = _delay_free_head;
        if (block->_free_time + 1000 < tick || block->_free_time > tick) {
            delay_free_one_block();
        } else {
            break;
        }
    }
}

void memory_watcher::delay_free_one_block()
{
    if (_delay_free_head == nullptr) return;

    auto block = _delay_free_head;
    _delay_free_head = _delay_free_head->_next;
    if (_delay_free_head == nullptr) {
        _delay_free_tail = nullptr;
    }

    if (!validate_block(block)) {
        report_heap_corruption(&block->_call_stack);
    } else {
        free_func(block->_start_ptr); /// delay free

        _delay_free_block--;
        _delay_free_memory_size -= block->_length;
        block_pool_free(block);
    }
}

bool memory_watcher::validate_block(memory_block* block)
{
    const uint8_t* data = (const uint8_t*)block->_start_ptr + block->_length;
    for (size_t i = 0; i < 16; i++) {
        if (data[i] != GUARD_NUM)
            return false;
    }
    return true;
}

memory_block* memory_watcher::check_is_delay_free(void* ptr)
{
    memory_block* curr = _delay_free_head;
    while (curr != nullptr) {
        if (curr->_start_ptr == ptr)
            return curr;

        curr = curr->_next;
    }

    return nullptr;
}

void memory_watcher::on_memory_alloc(void* start_ptr, uint32_t length)
{
    do_delay_free();

    auto block = block_pool_alloc();
    if (block == nullptr)
        return;

    /// 统计信息
    _current_block_count++;
    _current_memory_size += length;

    if (_current_block_count > _max_block_count) {
        _max_block_count = _current_block_count;
    }

    if (_current_memory_size > _max_memory_size) {
        _max_memory_size = _current_memory_size;
    }

    block->_start_ptr = start_ptr;
    block->_length = length;
    block->_call_stack.getstacktrace(CALLSTACKCHUNKSIZE,
        (SIZE_T*)TlsGetValue(_hook_state._storage_index));

    uint32_t slot_index = find_block(start_ptr);
    block->_next = _block_slots[slot_index];
    _block_slots[slot_index] = block;
    output_memory_info();
}

void memory_watcher::on_memory_realloc(void* old_ptr, void* new_ptr, uint32_t new_length)
{
    do_delay_free();

    /// 查找条目
    uint32_t slot_index = find_block(old_ptr);
    memory_block* prev = nullptr;
    memory_block* curr = _block_slots[slot_index];
    while (curr != nullptr && curr->_start_ptr != old_ptr) {
        prev = curr; curr = curr->_next;
    }

    /// 修改条目
    if (old_ptr == new_ptr && curr != nullptr) {
        _current_memory_size -= curr->_length;
        _current_memory_size += new_length;
        curr->_length = new_length;

        if (_current_memory_size > _max_memory_size) {
            _max_memory_size = _current_memory_size;
        }

        output_memory_info();
        return;
    }

    /// 移除条目
    if (curr != nullptr) {
        if (prev == nullptr) {
            _block_slots[slot_index] = curr->_next;
        } else {
            prev->_next = curr->_next;
        }

        _current_block_count--;
        _current_memory_size -= curr->_length;
        block_pool_free(curr);
    }

    /// 添加条目
    on_memory_alloc(new_ptr, new_length);
}

void memory_watcher::on_memory_free(void* start_ptr)
{
    do_delay_free();

    uint32_t slot_index = find_block(start_ptr);
    memory_block* prev = nullptr;
    memory_block* curr = _block_slots[slot_index];
    while (curr != nullptr) {
        if (curr->_start_ptr == start_ptr)
            break;

        prev = curr;
        curr = curr->_next;
    }

    if (curr == nullptr) {
        /// 检查double free
        memory_block* block = check_is_delay_free(start_ptr);
        if (block != nullptr) {
            report_heap_corruption(&curr->_call_stack);
        }

        /// 可能是调用其他函数分配出来的
        _not_freed_count++;
        return free_func(start_ptr);
    }

    if (prev == nullptr) {
        _block_slots[slot_index] = curr->_next;
    } else {
        prev->_next = curr->_next;
    }

    curr->_free_time = GetTickCount();
    curr->_next = nullptr;

    /// 放入delay free队列
    _delay_free_block++;
    _delay_free_memory_size += curr->_length;

    if (_delay_free_head == nullptr) {
        _delay_free_head = _delay_free_tail = curr;
    } else {
        _delay_free_tail->_next = curr;
        _delay_free_tail = curr;
    }

    /// 统计信息
    _current_block_count--;
    _current_memory_size -= curr->_length;
    output_memory_info();

    /// 立即删除
    /// do_delay_free(true);
}

void memory_watcher::on_shutdown()
{
    while (_delay_free_head != nullptr) {
        do_delay_free(true);
    }

    report_heap_leak();
}

uint32_t memory_watcher::find_block(void* start_ptr)
{
    uint32_t pos = (uint32_t)start_ptr;
    return pos / (1024 * 4);
}

void memory_watcher::report_heap_corruption(CallStack* call_stack)
{
    _hook_state._enabled = false;

    hook_state_prepare_stack_info();
    OutputDebugStringA("report_heap_corruption");

    call_stack->dump(FALSE);
    abort();
}

void report(LPCWSTR format, ...);

void memory_watcher::report_heap_leak()
{
    _hook_state._enabled = false;

    hook_state_prepare_stack_info();
    OutputDebugStringA("report_heap_leak\n");

    uint32_t index = 0;
    for (auto block : _block_slots) {
        while (block != nullptr) {
            report(L"heap_leak(%05d), %p, %d\n",
                ++index, block->_start_ptr, block->_length);
            block->_call_stack.dump(FALSE);
            block = block->_next;
        }
    }

    output_memory_info(true);
}

#include <stdio.h>

void memory_watcher::output_memory_info(bool force)
{
    DWORD tick = GetTickCount();
    if (force || _last_output_time + 10000 < tick || tick < _last_output_time) {
        _last_output_time = tick;

        _hook_state._enabled = false; /// 防止内部使用函数造成嵌套

        char not_freed_count_buffer[64];
        sprintf_s(not_freed_count_buffer, "not_freed_count, %d\n", _not_freed_count);
        OutputDebugStringA(not_freed_count_buffer);

        char delay_free_block_count_buffer[64];
        sprintf_s(delay_free_block_count_buffer, "delay_free_block_count, %d\n", _delay_free_block);
        OutputDebugStringA(delay_free_block_count_buffer);

        char delay_free_memory_size_buffer[64];
        sprintf_s(delay_free_memory_size_buffer, "delay_free_memory_size, %d\n", _delay_free_memory_size / 1024);
        OutputDebugStringA(delay_free_memory_size_buffer);

        char block_count_buffer[64];
        sprintf_s(block_count_buffer, "block_count, %d\n", _current_block_count);
        OutputDebugStringA(block_count_buffer);

        char memory_size_buffer[64];
        sprintf_s(memory_size_buffer, "memory_size, %d\n", _current_memory_size / 1024);
        OutputDebugStringA(memory_size_buffer);

        char max_block_count_buffer[64];
        sprintf_s(max_block_count_buffer, "max_block_count, %d\n", _max_block_count);
        OutputDebugStringA(max_block_count_buffer);

        char max_memory_size_buffer[64];
        sprintf_s(max_memory_size_buffer, "max_memory_size, %d\n", _max_memory_size / 1024);
        OutputDebugStringA(max_memory_size_buffer);

        _hook_state._enabled = true;
    }
}
