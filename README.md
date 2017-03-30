# memory_watcher
base on @Visual Leak Detector and @mhook, 但是mhook没有提交上来

使用了VLD里面的获取堆栈和输出堆栈的功能，使用了mhook里面的函数挂钩功能，挂钩内存分配函数。对VLD和mhook代码进行了一些修改。自己实现的代码就两个memory_watcher，目前没有细致的测试


