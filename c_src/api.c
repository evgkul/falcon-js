#include <stdio.h>
#include <emscripten.h>
#include <stdint.h>
#include <stdlib.h>

struct sized_array {
    uint32_t size;
    uint8_t array[];
};

EMSCRIPTEN_KEEPALIVE
struct sized_array* printFirst(){
    printf("Helloworld");
    struct sized_array *p1 = malloc(20+4);
    p1->size = 20;
    p1->array[2] = 2;
    return p1;
}

EMSCRIPTEN_KEEPALIVE
int size_t_size(){
    return sizeof(size_t);
}
