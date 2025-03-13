SECTIONS {
    .my_main        0x406DB7 : { *(.my_main)  *(.my_main_string) *(.my_other_functions) }
    .func_fxprintf   0x5718c0  : { *(.func_fxprintf) }    
    .func_snprintf 0x5e8d10 : { *(.func_snprintf) }
    .func_get_nanosecond 0x491470 : { *(.func_mw_get_time_seed) }
    .func_generate_random 0x455f40 : { *(.func_mw_keygen) }
    .func_malloc 0x5830f0 : { *(.func_malloc) }
    .func_memset 0x401100 : { *(.func_memset) }
    .func_memcpy 0x4010e0 : { *(.func_memcpy) }
    .func_mprotect 0x5d54b0 : { *(.func_mprotect) }    
    .func_getpagesize 0x5d5180  : { *(.func_getpagesize) }
    .func_fork 0x5d2900 : { *(.func_fork) }
    .data_ransom_note 0x6a7640  : { *(.data_ransom_note) }
    .data_counter 0x6b75b0 : { *(.data_counter) }
    .data_writable_global 0x6B75BA : { *(.data_writable_global) }
}