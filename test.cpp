#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <string>
#include <sstream>

bool hook_state_initialize();

void hook_state_uninitialize();

class auto_hook_state
{
public:
    auto_hook_state()
    {
        hook_state_initialize();
    }

    ~auto_hook_state()
    {
        hook_state_uninitialize();
    }
};

void test_func()
{
    free(malloc(800));

    void * q = malloc(8);
    void * p = realloc(q, 1024);
    free(p);
}

int main()
{
    auto_hook_state www;
    test_func();
    return 0;
}
