#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int main(void) {
    errno = 0;
    long result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    printf(
        "ptrace(PTRACE_TRACEME) = %ld, errno = %d (%s)\n",
        result,
        errno,
        strerror(errno)
    );

    if (result != -1) {
        return 1;
    }

    return errno == EPERM ? 42 : 2;
}
