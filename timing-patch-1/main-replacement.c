#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <time.h>

#define DUMMY_EXTERNAL_FUNCTION __attribute__((naked)) __attribute__((noinline))
#define USE_SECTION(x) __attribute__((section(x)))
#define USE_STRING_SECTION __attribute__((section(".my_main_string")))

// LIBC functions

// NOTE: the addresses must be set in linker_script.ld

// malloc
void *DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_malloc") my_malloc(size_t size)
{
}
// memcpy
void DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_memcpy") my_memcpy(void *dest, const void *src, size_t n)
{
}
// memset
void DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_memset") my_memset(void *s, int c, size_t n)
{
}

// mprotect
int DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_mprotect") my_mprotect(void *addr, size_t len, int prot)
{
}

// fxprintf (when handle is NULL, it will output to stderr)
int DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_fxprintf") fxprintf(void *handle, const char *format, ...)
{
}

//snprintf
int DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_snprintf") my_snprintf(char *str, size_t size, const char *format, ...)
{
}

// getpagesiz
size_t DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_getpagesize") my_getpagesize()
{
}

uint64_t DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_get_nanosecond") get_nanosecond()
{
}

void DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_generate_random") generate_random(void *dummy, int len, uint8_t *result)
{
}

// fork
int DUMMY_EXTERNAL_FUNCTION USE_SECTION(".func_fork") my_fork()
{
}

// DATA in binary



volatile uint64_t *ransom_note USE_SECTION(".data_ransom_note") = 0;

volatile uint32_t *volatile data_counter USE_SECTION(".data_counter") = 0;

//------------------------------------------------------------------------
// Main function
//------------------------------------------------------------------------

int tmp_time USE_SECTION(".data_writable_global") = 0;

uint64_t USE_SECTION(".my_other_functions") my_fake_time(int clock, struct timespec *tp)
{
    tp->tv_sec = 0;
    tp->tv_nsec = 0;
    // tp->tv_nsec = tmp_time;
    // tmp_time++;
    return 0;
}


//unbuffered write to stdout
void USE_SECTION(".my_other_functions") my_puts(const char *s) {
    int len = 0;
    while (s[len] != '\0')
    {
        len++;
    }
    asm volatile(
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "movslq %1, %%rdx\n"  // sign extend 32-bit len to 64-bit
        "syscall\n"
        :
        : "r"(s), "r"(len)
        : "rax", "rdi", "rsi", "rdx");
}


int USE_SECTION(".my_main") mymain(int argc, char *argv[])
{

    static const char fmt[] USE_STRING_SECTION = "Time seed: %d '%lld' to '%lld'\n";
    static const char fmt_diff[] USE_STRING_SECTION = "Diff: %d :%lld\n";    
    static const char fmt_hex[] USE_STRING_SECTION = "%02x";
    static const char fmt_int[] USE_STRING_SECTION = "%d\n";
    static const char fmt_ptr[] USE_STRING_SECTION = "%p\n";
    static const char fmt_enter[] USE_STRING_SECTION = "\n";
    static const char fmt_ptrnow[] USE_STRING_SECTION = "Pointer now: %p\n";


    int page_size = my_getpagesize();
    fxprintf(0, fmt_int, page_size);


    void *tmp1 = my_malloc(32);
    void *tmp2 = my_malloc(16);
    void *tmp3 = my_malloc(16);
    void *tmp4 = my_malloc(16);

#define MAX_TEST 1000
    unsigned char **tmp_all = my_malloc(MAX_TEST * sizeof(unsigned char *));
    for (int i = 0; i < MAX_TEST; i++) {
        asm volatile("" ::: "memory"); 
        tmp_all[i] = my_malloc(80);
        my_memset(tmp_all[i], 0, 80);

    }

    int errno;
    errno = 0;
    
    uint64_t *time_start = my_malloc(MAX_TEST * sizeof(uint64_t));
    uint64_t *time_end = my_malloc(MAX_TEST * sizeof(uint64_t));

    for (int i =0; i < MAX_TEST; i++) {
        my_memset(tmp1, 0, 32);
        my_memset(tmp2, 0, 16);
        my_memset(tmp3, 0, 16);
        my_memset(tmp4, 0, 16);
        generate_random(0, 32, tmp1);
        generate_random(0, 16, tmp2);
        asm volatile("" ::: "memory");  // Prevent compiler optimizations        
        time_start[i] = get_nanosecond();
        generate_random(0, 16, tmp3);
        //generate_random(0, 16, tmp4);
            
        asm volatile("" ::: "memory");  // Prevent compiler optimizations                        
        time_end[i] = get_nanosecond();                
        unsigned char *dest = tmp_all[i];
        my_memcpy(dest, tmp1, 32);
        my_memcpy(dest + 32, tmp2, 16);
        my_memcpy(dest + 48, tmp3, 16);
        my_memcpy(dest + 64, tmp4, 16);
    }
    for (int i =0; i < MAX_TEST; i++) {
        fxprintf(0, fmt, i, time_start[i], time_end[i]);
        uint64_t time_diff = time_end[i] - time_start[i];
        fxprintf(0, fmt_diff, i, time_diff);
        //dump the buffer
        asm volatile("" ::: "memory");
        // unsigned char *dest = tmp_all[i];
        // for (int j = 0; j < 80; j++) {
        //     fxprintf(0, fmt_hex, dest[j]);
        // }
        // fxprintf(0, fmt_enter);
    }
}

int main() { return 0; }
