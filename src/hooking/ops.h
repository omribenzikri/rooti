#ifndef _ROOTI_HOOKING_OPS_H
#define _ROOTI_HOOKING_OPS_H

// Shorthand for initializing operation hook objects
#define ROOTI_OPS_HOOK(_symbol, _ops, _hook, _orig) \
{ \
    .symbol = (_symbol), \
    .func = (_hook), \
    .orig = (_orig), \
    .ops = (_ops) \
}

// The different types of (supported) file operations
enum rooti_file_ops {
    ROOTI_FILE_READ_ITER,
    ROOTI_FILE_WRITE_ITER
};

// The different types of seqfile operations 
enum rooti_seq_ops {
    ROOTI_SEQ_START,
    ROOTI_SEQ_STOP,
    ROOTI_SEQ_NEXT,
    ROOTI_SEQ_SHOW
};

// Represents a hook to a file operation
struct rooti_file_ops_hook {
    char *symbol;             // name of the file_operations object symbol
    void *func;               // pointer to hook function
    void *orig;               // pointer to the original function
    enum rooti_file_ops ops;  // the desired operation to hook
};

// Represents a hook to a seqfile operation
struct rooti_seq_ops_hook {
    char *symbol;             // name of the seq_operations object symbol
    void *func;               // pointer to hook function
    void *orig;               // pointer to the original function
    enum rooti_seq_ops ops;   // the desired operation to hook
};

int rooti_install_file_ops_hook(struct rooti_file_ops_hook *hook);
int rooti_install_file_ops_hooks(struct rooti_file_ops_hook *hooks, size_t count);
int rooti_uninstall_file_ops_hook(struct rooti_file_ops_hook *hook);
int rooti_uninstall_file_ops_hooks(struct rooti_file_ops_hook *hooks, size_t count);

int rooti_install_seq_ops_hook(struct rooti_seq_ops_hook *hook);
int rooti_install_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count);
int rooti_uninstall_seq_ops_hook(struct rooti_seq_ops_hook *hook);
int rooti_uninstall_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count);

#endif