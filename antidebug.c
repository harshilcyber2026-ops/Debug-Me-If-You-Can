/*
 * FlagVault CTF -- "Debug Me If You Can"
 * Category: Reverse Engineering / Anti-Debug
 * Difficulty: Hard | Points: 500
 *
 * Three anti-debug layers:
 *   1. ptrace self-detection
 *   2. rdtsc timing check
 *   3. CRC32 code integrity check
 *
 * Flag: FlagVault{4nt1_d3bug_byp4ss_m4st3r}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdint.h>

/* FLAG XOR'd with 0xAB */
static const unsigned char FLAG_ENC[] = {
    0xed,0xc7,0xca,0xcc,0xfd,0xca,0xde,0xc7,0xdf,0xd0,
    0x9f,0xc5,0xdf,0x9a,0xf4,0xcf,0x98,0xc9,0xde,0xcc,
    0xf4,0xc9,0xd2,0xdb,0x9f,0xd8,0xd8,0xf4,0xc6,0x9f,
    0xd8,0xdf,0x98,0xd9,0xd6
};
#define FLAG_LEN (sizeof(FLAG_ENC)/sizeof(FLAG_ENC[0]))

/* Layer 1: ptrace self-check */
static int check_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    return 0;
}

/* Layer 2: rdtsc timing */
static inline uint64_t rdtsc_val(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int check_timing(void) {
    uint64_t t1 = rdtsc_val();
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    uint64_t t2 = rdtsc_val();
    (void)x;
    return ((t2 - t1) > 500000ULL) ? 1 : 0;
}

/* Layer 3: CRC32 code integrity */
static uint32_t crc32_step(uint32_t crc, uint8_t b) {
    crc ^= b;
    for (int i = 0; i < 8; i++)
        crc = (crc >> 1) ^ (0xEDB88320u * (crc & 1u));
    return crc;
}

static uint32_t g_expected_crc = 0;
static int      g_crc_init     = 0;

static uint32_t compute_crc(void) {
    const uint8_t *p = (const uint8_t *)check_ptrace;
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < 64; i++)
        crc = crc32_step(crc, p[i]);
    return crc ^ 0xFFFFFFFFu;
}

static int check_integrity(void) {
    uint32_t c = compute_crc();
    if (!g_crc_init) {
        g_expected_crc = c;
        g_crc_init = 1;
        return 0;
    }
    return (c != g_expected_crc) ? 1 : 0;
}

/* Decode flag */
static void decode_flag(char *out) {
    for (size_t i = 0; i < FLAG_LEN; i++)
        out[i] = (char)(FLAG_ENC[i] ^ 0xABu);
    out[FLAG_LEN] = '\0';
}

int main(void) {
    fprintf(stdout, "\n[*] FlagVault CTF :: Debug Me If You Can\n");
    fprintf(stdout, "[*] Running anti-debug checks...\n\n");
    fflush(stdout);

    check_integrity();

    int fail = 0;

    fprintf(stdout, "[.] Check 1/3  ptrace detection ..... ");
    fflush(stdout);
    if (check_ptrace()) { fprintf(stdout, "DETECTED\n"); fail = 1; }
    else                  fprintf(stdout, "PASS\n");

    fprintf(stdout, "[.] Check 2/3  timing analysis ...... ");
    fflush(stdout);
    if (check_timing()) { fprintf(stdout, "ANOMALY\n"); fail = 1; }
    else                  fprintf(stdout, "PASS\n");

    fprintf(stdout, "[.] Check 3/3  code integrity ....... ");
    fflush(stdout);
    if (check_integrity()) { fprintf(stdout, "TAMPERED\n"); fail = 1; }
    else                     fprintf(stdout, "PASS\n");

    fprintf(stdout, "\n");

    if (fail) {
        fprintf(stdout, "[-] Debugger or tampering detected. No flag.\n\n");
        return 1;
    }

    char flag[64];
    decode_flag(flag);
    fprintf(stdout, "[+] All checks passed!\n");
    fprintf(stdout, "[+] Flag: %s\n\n", flag);
    return 0;
}
