#pragma once

extern "C"  { 
const void *enable_memory_tracing(bool usable_size, bool unw);
const void *disable_memory_tracing();
const void *dump_memory_tracing();
void *get_tracing_shared_data();
const void *set_memory_tracing_file(const char *file_name);
}
