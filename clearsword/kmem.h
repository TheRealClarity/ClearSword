#ifndef kmem_h
#define kmem_h

#include "common.h"

uint64_t find_self_proc(void);
uint64_t task_from_proc(uint64_t proc);
uint64_t pmap_from_task(uint64_t task);

#endif /* kmem_h */
