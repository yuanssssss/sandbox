#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t parse_mebibytes(const char *raw) {
    char *end = NULL;
    unsigned long long value = strtoull(raw, &end, 10);

    if (raw[0] == '\0' || end == raw || (end != NULL && *end != '\0')) {
        fprintf(stderr, "invalid MiB value: %s\n", raw);
        exit(2);
    }

    return (size_t)value;
}

int main(int argc, char **argv) {
    const size_t mib = argc > 1 ? parse_mebibytes(argv[1]) : 64U;
    const size_t bytes = mib * 1024ULL * 1024ULL;
    long page_size = sysconf(_SC_PAGESIZE);

    if (page_size <= 0) {
        page_size = 4096;
    }

    printf("allocating %zu MiB (%zu bytes)\n", mib, bytes);

    unsigned char *buffer = malloc(bytes);
    if (buffer == NULL) {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        return 1;
    }

    for (size_t offset = 0; offset < bytes; offset += (size_t)page_size) {
        buffer[offset] = (unsigned char)(offset / (size_t)page_size);
    }
    if (bytes > 0) {
        buffer[bytes - 1] = 0xAA;
    }

    puts("memory touched successfully");
    sleep(1);
    free(buffer);
    return 0;
}
