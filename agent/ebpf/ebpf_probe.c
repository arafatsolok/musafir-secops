// eBPF probe for Linux kernel monitoring
// This is a simplified example - in production, use libbpf or cilium/ebpf

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/version.h>

// Define the eBPF map for storing events
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 0,
};

// Event structure to send to userspace
struct event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
    __u32 syscall;
    __u64 timestamp;
};

// Trace execve syscalls
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event evt = {};
    
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.syscall = ctx->id;
    evt.timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    // Get filename from arguments
    char* filename = (char*)ctx->args[0];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Trace file operations
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter* ctx) {
    struct event evt = {};
    
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.syscall = ctx->id;
    evt.timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    // Get filename from arguments
    char* filename = (char*)ctx->args[1];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
