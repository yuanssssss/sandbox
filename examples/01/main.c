#include <stdio.h>

#include "extra.h"

int main(void) {
    const int lhs = 5;
    const int rhs = 3;

    printf("Hello from examples/01\n");
    printf("%d + %d = %d\n", lhs, rhs, add(lhs, rhs));
    printf("%d * %d = %d\n", lhs, rhs, multiply(lhs, rhs));

    return 0;
}
