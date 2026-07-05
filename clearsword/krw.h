#ifndef krw_h
#define krw_h

#include "common.h"

#define CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE 0x20
#define EARLY_KRW_LENGTH 0x20  // 32

uint64_t early_kread64(uint64_t where);
void early_kwrite64(uint64_t where, uint64_t what);
void kread_length(uint64_t address, void* buffer, uint64_t size);
void kwrite_length(uint64_t dst, void* src, uint64_t size);
bool kwrite_zone_element(uint64_t dst, void* src, uint64_t len);

#endif /* krw_h */
