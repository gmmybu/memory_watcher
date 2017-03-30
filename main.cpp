#include <stdint.h>
#include <windows.h>
#include <vector>
#include "mhook-lib/mhook.h"
#include "dbghelpapi.h"
#include "callstack.h"
#include "memory_watcher.h"

void test_func()
{
    std::vector<uint32_t> data(800 * 400);
    data.push_back(3);

    int* i = new int[4];
    i[5] = 8;
    i[6] = 8;
    i[7] = 8;

    delete[] i;

    Sleep(2000);

    std::vector<uint32_t> kk(200);
}

bool hook_state_initialize();

void hook_state_uninitialize();

int main()
{
    hook_state_initialize();

    OutputDebugStringA("before func\n");
    test_func();
    OutputDebugStringA("after func\n");

    hook_state_uninitialize();
    while (true);
    return 0;
}
