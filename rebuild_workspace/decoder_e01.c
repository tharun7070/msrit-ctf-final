#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Obfuscated base-41 pager packet decoder */
static const char BASE41_ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyz_!@#$";
#define BASE_RADIX 41

static int get_char_index(char c) {
    for (int i = 0; i < BASE_RADIX; i++) {
        if (BASE41_ALPHABET[i] == c) {
            return i;
        }
    }
    return -1;
}

/* Decodes base-41 string into bytes */
void decode_token(const char *input, unsigned char *out_buf, size_t *out_len) {
    __int128 val = 0;
    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        int idx = get_char_index(input[i]);
        if (idx < 0) {
            fprintf(stderr, "[-] Invalid token character '%c'\n", input[i]);
            exit(1);
        }
        val = val * BASE_RADIX + idx;
    }

    /* Extract big-endian bytes */
    unsigned char temp[32];
    int bytes_count = 0;
    while (val > 0) {
        temp[bytes_count++] = (unsigned char)(val & 0xFF);
        val >>= 8;
    }

    *out_len = bytes_count;
    for (int i = 0; i < bytes_count; i++) {
        out_buf[i] = temp[bytes_count - 1 - i];
    }
    out_buf[bytes_count] = '\0';
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("=========================================\n");
        printf(" LESTER SECURE PAGER RELAY v4.1 (REL-X)  \n");
        printf("=========================================\n");
        printf("Usage: %s <base-token> [more tokens...]\n", argv[0]);
        return 1;
    }

    for (int arg = 1; arg < argc; arg++) {
        unsigned char decoded[64];
        size_t len = 0;
        decode_token(argv[arg], decoded, &len);
        printf("%s", decoded);
    }
    printf("\n");
    return 0;
}
