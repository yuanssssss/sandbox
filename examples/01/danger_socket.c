#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    errno = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    printf(
        "socket(AF_INET, SOCK_STREAM, 0) = %d, errno = %d (%s)\n",
        fd,
        errno,
        strerror(errno)
    );

    if (fd >= 0) {
        close(fd);
        return 1;
    }

    return errno == EPERM ? 42 : 2;
}
