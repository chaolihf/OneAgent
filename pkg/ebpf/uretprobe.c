//go:build ignore

//#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

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
    u64 mode;
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


// SEC("kprobe/vfs_open")
// int trace_vfs_open(struct pt_regs *ctx)
// {
    
//     struct path *p = (struct path*)PT_REGS_PARM1(ctx);
//     struct dentry *de;
//     bpf_probe_read_kernel(&de,sizeof(void*),&p->dentry);
//     struct qstr d_name;
//     bpf_probe_read_kernel(&d_name,sizeof(d_name),&de->d_name);
//     char filename[32];
//     bpf_probe_read_kernel(&filename,sizeof(filename),d_name.name);
//     if (d_name.len == 0)
//         return 0;
//     u64 pid = bpf_get_current_pid_tgid();
//     struct fileEvent *fileEventInfo;
//     fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
//     if (!fileEventInfo) {
// 		return 0;
// 	}
//     fileEventInfo->pid = pid;
//     bpf_get_current_comm(&fileEventInfo->comm, TASK_COMM_LEN);
//     bpf_probe_read(&fileEventInfo->filename,sizeof(&fileEventInfo->filename),filename);
//     bpf_ringbuf_submit(fileEventInfo, 0);
//     return 0;
// };


// SEC("kprobe/vfs_open")
// int BPF_KPROBE(vfs_open,const struct path *path, struct file *file)
// {
// 	pid_t pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	const unsigned char *filename;
//     // 一行语句就实现了链式的读取
// 	filename = BPF_CORE_READ(path,dentry,d_name.name);
// 	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
//     // u64 pid = bpf_get_current_pid_tgid();
//     // struct fileEvent *fileEventInfo;
//     // fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
//     // if (!fileEventInfo) {
// 	// 	return 0;
// 	// }
//     // fileEventInfo->pid = pid;
//     // bpf_get_current_comm(&fileEventInfo->comm, TASK_COMM_LEN);
//     // bpf_probe_read(&fileEventInfo->filename,sizeof(&fileEventInfo->filename),filename);
//     // bpf_ringbuf_submit(fileEventInfo, 0);
// 	return 0;
// }

//重写变量值，0x100000对应的是文件创建模式，可以在启动时修改其他值来实现对不同模式的指定
volatile const u64 catchFileMode=0x100000;
/**
 * 如何知道参数的类型和数据，如vfs_open函数，可以查找
 * https://github.com/torvalds/linux/blob/45ec2f5f6ed3ec3a79ba1329ad585497cdcbe663/fs/open.c#L1084
 * 原型为
 * int vfs_open(const struct path *path, struct file *file)
 * 这样就可以通过PT_REGS_PARM1来获取path数据，PT_REGS_PARM2获取file参数
*/
// SEC("kprobe/vfs_open")
// int trace_vfs_open(struct pt_regs *ctx)
// {
// 	pid_t pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	const unsigned char *filename;
//     // 一行语句就实现了链式的读取
//     struct path *p = (struct path*)PT_REGS_PARM1(ctx);
// 	filename = BPF_CORE_READ(p,dentry,d_name.name);

//     struct file *f=(struct file*)PT_REGS_PARM2(ctx);
// 	int fmode = BPF_CORE_READ(f, f_mode);

// 	if (!(fmode & FMODE_CREATED))
// 		return 0;
//     bpf_printk("KPROBE ENTRY pid = %d, filename = %s , rewrite value=%d\n", pid, filename,latency_thresh);
    
    
//     // u64 pid = bpf_get_current_pid_tgid();
//     // struct fileEvent *fileEventInfo;
//     // fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
//     // if (!fileEventInfo) {
// 	// 	return 0;
// 	// }
//     // fileEventInfo->pid = pid;
//     // bpf_get_current_comm(&fileEventInfo->comm, TASK_COMM_LEN);
//     // bpf_probe_read(&fileEventInfo->filename,sizeof(&fileEventInfo->filename),filename);
//     // bpf_ringbuf_submit(fileEventInfo, 0);
// 	return 0;
// }

/*
    通过这个结构来动态修改数据
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u64);
    __type(value, u64);
} fileModeMap SEC(".maps");


/*
   product version
*/
SEC("kprobe/vfs_open")
int trace_vfs_open(struct pt_regs *ctx)
{
	const unsigned char *filename;
    struct path *p = (struct path*)PT_REGS_PARM1(ctx);
	filename = BPF_CORE_READ(p,dentry,d_name.name);
    struct file *f=(struct file*)PT_REGS_PARM2(ctx);
	int fmode = BPF_CORE_READ(f, f_mode);
    u64 *v = NULL;
    u64 *key=0;
    v = bpf_map_lookup_elem(&fileModeMap, &key);
    u64 mode=catchFileMode;
    if (v != NULL) {
        mode=*v;
    }
	if (!(fmode & mode))
		return 0;
    
    u64 pid = bpf_get_current_pid_tgid();
    struct fileEvent *fileEventInfo;
    fileEventInfo = bpf_ringbuf_reserve(&fileEvents, sizeof(struct fileEvent), 0);
    if (!fileEventInfo) {
		return 0;
	}
    fileEventInfo->pid = pid;
    fileEventInfo->mode=mode;
    bpf_get_current_comm(&fileEventInfo->comm, TASK_COMM_LEN);
    bpf_probe_read(&fileEventInfo->filename,sizeof(&fileEventInfo->filename),filename);
    bpf_ringbuf_submit(fileEventInfo, 0);
	return 0;
}

//查看/sys/kernel/tracing/events/syscalls来获取所有的tracing

struct data_args_t
{
    __s32 fd;
    uintptr_t buf;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");


static inline void process_data(struct trace_event_raw_sys_exit *ctx,
                                u64 id, const struct data_args_t *args, u64 bytes_count)
{
    if (args->buf == 0)
    {
        return;
    }
    u32 pid = id >> 32;
    u64 pid_fd = ((u64)pid << 32) | (u64)args->fd;
    bpf_printk("pid %d read %d",pid,pid_fd);
    return;
}


SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();

    struct data_args_t read_args = {};
    read_args.fd = (int)BPF_CORE_READ(ctx, args[0]);
    read_args.buf = (uintptr_t)BPF_CORE_READ(ctx, args[1]);
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    u64 bytes_count = (u64)BPF_CORE_READ(ctx, ret);
    if (bytes_count <= 0)
    {
        return 0;
    }
    u64 id = bpf_get_current_pid_tgid();
    struct data_args_t *read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL)
    {
        process_data(ctx, id, read_args, bytes_count);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);

    return 0;
}

struct accept_args_t
{
    struct sockaddr_in *addr;
};


SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
    bpf_printk("enter_accept accept_args.addr: %llx\n", accept_args.addr);
    return 0;
}

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} socketEvents SEC(".maps");

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14
#define MAX_BUF_SIZE 64
#define ETH_P_IP 0x0800

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
	__u32 payload_length;
    __u8 payload[MAX_BUF_SIZE];
};

// Force emitting struct so_event into the ELF.
const struct so_event *useSocketEventForGo __attribute__((unused));

struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;
	if (ip_is_fragment(skb, nhoff))
		return 0;
    
	// // ip4 header lengths are variable
	// // access ihl as a u8 (linux/include/linux/skbuff.h)
	bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
	hdr_len &= 0x0f;
	hdr_len *= 4;
	/* verify hlen meets minimum size requirements */
	if (hdr_len < sizeof(struct iphdr))
	{
		return 0;
	}

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

	if (ip_proto != IPPROTO_TCP)
	{
		return 0;
	}

	tcp_hdr_len = nhoff + hdr_len;
	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

	__u8 doff;
	bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
	doff &= 0xf0;																						// clean-up res1
	doff >>= 4;																							// move the upper 4 bits to low
	doff *= 4;																							// convert to bytes length

	payload_offset = ETH_HLEN + hdr_len + doff;
	payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

	char line_buffer[7];
	if (payload_length < 7 || payload_offset < 0)
	{
		return 0;
	}
	bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
	if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
		bpf_strncmp(line_buffer, 4, "POST") != 0 &&
		bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
		bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
		bpf_strncmp(line_buffer, 4, "HTTP") != 0)
	{
		return 0;
	}
	bpf_printk("receive http request %d len %d buffer: %s\n", payload_offset, payload_length, line_buffer);

	// /* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&socketEvents, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ip_proto = ip_proto;
	bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;

	e->payload_length = payload_length;
	bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	bpf_ringbuf_submit(e, 0);

	return skb->len;
}