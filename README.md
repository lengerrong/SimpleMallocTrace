# SimpleMallocTrace
Simple malloc trace to detect memory leak in a c/c++ program

 Use dlsym() to hook libc malloc functions in __attribute__((constructor)) function which would be called before main().
 Implementation malloc/free ... functions with the hooked functions and record memory alloc/free history, specially store 
 backtrace for all alloced memory.
 Detect memory leak in __attribute__((distructor)) function which would be called after main().
