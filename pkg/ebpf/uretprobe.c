//go:build ignore

//#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_tracing.h"
//#include <linux/fs.h>
//#include <linux/sched.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 line[80];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));



SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
	struct event event;

	event.pid = bpf_get_current_pid_tgid();
	bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

// count_packets atomically increases a packet counter on every invocation.
SEC("xdp") 
int count_packets() {
    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }

    return XDP_PASS; 
}

SEC("kprobe/sys_execve")
int helloWorld(void *context){
    char message[]="hello world";
    bpf_trace_printk(message,sizeof(message));
    return 0;
}


#define DNAME_INLINE_LEN 256
struct fileEvent {
    u32 pid;
    u8 comm[TASK_COMM_LEN];
    u8 filename[DNAME_INLINE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} fileEvents SEC(".maps");

// Force emitting struct fileEvent into the ELF.
const struct fileEvent *useFileEventForGo __attribute__((unused));



// SEC("kprobe/vfs_create")
// int trace_create(struct pt_regs *ctx, struct mnt_idmap *idmap,
//         struct inode *dir, struct dentry *dentry){
//     struct fileEvent *fileEventInfo;
//     fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
//     if (!fileEventInfo) {
// 		return 0;
// 	}
//     fileEventInfo->pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_get_current_comm(&fileEventInfo->comm, sizeof(fileEventInfo->comm));
//     bpf_probe_read_kernel(&fileEventInfo->filename, sizeof(fileEventInfo->filename), 
//         (void *)dentry->d_name.name);
    
    
//     bpf_ringbuf_submit(fileEventInfo, 0);


//     return 0;
// }


SEC("kprobe/vfs_open")
int trace_vfs_open(struct pt_regs *ctx)
{
    
    struct path *p = (struct path*)PT_REGS_PARM1(ctx);
    struct dentry *de;
    bpf_probe_read_kernel(&de,sizeof(void*),&p->dentry);
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name,sizeof(d_name),&de->d_name);
    char filename[32];
    bpf_probe_read_kernel(&filename,sizeof(filename),d_name.name);
    if (d_name.len == 0)
        return 0;
    u64 pid = bpf_get_current_pid_tgid();
    struct fileEvent *fileEventInfo;
    fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
    if (!fileEventInfo) {
		return 0;
	}
    fileEventInfo->pid = pid;
    bpf_get_current_comm(&fileEventInfo->comm, TASK_COMM_LEN);
    bpf_probe_read(&fileEventInfo->filename,sizeof(&fileEventInfo->filename),filename);
    bpf_ringbuf_submit(fileEventInfo, 0);
    return 0;
};