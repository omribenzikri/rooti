#include <linux/linkage.h>
#include <asm/frame.h>

.global rooti_free_mod_mem
.type rooti_free_mod_mem, @function

SYM_FUNC_START(rooti_free_mod_mem)
    # Setting up a stack frame just to satisfy objtool
    FRAME_BEGIN

    movq (rooti_data_section_base), %r8
    movq (rooti_rodata_section_base), %r9
    movq (rooti_text_section_base), %r10

    movq %r8, %rdi
    call vfree

    movq %r9, %rdi
    call vfree

    FRAME_END

    # We have to jump instead of tail calling since the text
    # section would be freed by the time we return from vfree
    movq %r10, %rdi
    jmp vfree
SYM_FUNC_END(rooti_free_mod_mem)
