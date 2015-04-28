#ifndef _SimpleMallocTrace_h
#define _SimpleMallocTrace_h

extern "C" {

size_t smtstart(const char* file, const char* function, size_t line);
void smtstop(size_t, const char* file, const char* function, size_t line);

}

#endif // _SimpleMallocTrace_h
