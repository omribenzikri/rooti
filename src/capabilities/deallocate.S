#include <linux/linkage.h>

.global rooti_self_deallocate
.type rooti_self_deallocate, @function

SYM_FUNC_START(rooti_self_deallocate)
    pushq %rbp
    movq %rsp, %rbp

    # insert a small delay to make sure the module code that scheduled this function
    # finishes servicing the system call before we get rid of its memory.
    mov $1000, %rdi
    call msleep
    popq %rbp

    # indirect jump to free_module(), we can't call the function because returning from
    # it means returning to instructions in already freed memory. After free_module() completes
    # we return to the caller of this function (the return addr at the top of the stack doesn't change).
    mov this_module_ptr, %rdi
    mov free_module_ptr(%rip), %rax
    jmp __x86_indirect_thunk_rax
SYM_FUNC_END(rooti_self_deallocate)
