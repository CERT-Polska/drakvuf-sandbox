ENTRY(_start)

PHDRS {
    text PT_LOAD FLAGS(7);   /* R-X */
}
SECTIONS
{
    .text : SUBALIGN(16)
    {
        *(.startup)
        *(.text)
        *(.text.*)
        *(.data)
        *(.data.*)
        *(.rodata)
        *(.rodata.*)
    } :text

    .bss : SUBALIGN(16)
    {
        bss_start = .;
        *(.bss)
        *(.bss.*)
        bss_end = .;
    }

    /DISCARD/ : {
        *(.comment)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
        *(.hash)
        *(.eh_frame_hdr)
        *(.eh_frame)
        *(.dynamic)
    }
}
