#include <stdio.h>

int main(void) {
    volatile unsigned long long counter = 0;

    puts("entering busy loop");
    while (1) {
        counter++;
        if ((counter & ((1ULL << 28) - 1)) == 0) {
            fprintf(stderr, "counter=%llu\n", counter);
        }
    }
}
