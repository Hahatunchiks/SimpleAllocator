#include "mem.h"
#include "util.h"
#include "mem_internals.h"

#include <stdio.h>
#include <stdlib.h>

int main() {

    printf("Init heap\n");

    const size_t heap_size = 10;
    void *heap = heap_init(heap_size);
    debug_heap(stdout, heap);

    printf("Test 1: Successful allocation\n\n");
    printf("Test1: check _malloc function\n");

    const size_t query = 10;
    void *mem_res = _malloc(query);
    if (mem_res == NULL) {
        printf("hmm\n");
    } else {
        printf("Test1: success on allocation on %p address \n", mem_res);
        printf("Test1: check free function:\n");
        debug_heap(stdout, heap);
        debug_struct_info(stdout, mem_res);
        _free(mem_res);
        debug_heap(stdout, heap);

    }
    printf("--------\n\n");


    printf("Test 2: Free one of the several blocks");

    const size_t query_one = 10;
    const size_t query_two = 20;
    const size_t query_three = 30;

    void *mem_res_one = _malloc(query_one);
    void *mem_res_two = _malloc(query_two);
    void *mem_res_three = _malloc(query_three);
    debug_heap(stdout, heap);
    _free(mem_res_two);
    debug_heap(stdout, heap);
    printf("Test 3: Free two of the several blocks");
    mem_res_two = _malloc(query_two);
    _free(mem_res_three);
    _free(mem_res_one);
    debug_heap(stdout, heap);
    _free(mem_res_two);
    debug_heap(stdout, heap);


    printf("Test 4: New region is not close to the old");

    void *mem_res_zero_4 = _malloc(8188);
    int *mem_res_one_4 = _malloc(2000);
    *mem_res_one_4 = 4;
    debug_heap(stdout, heap);
    long long *mem_res_two_4 = _malloc(8000);
    *mem_res_two_4 = 23;
    debug_heap(stdout, heap);

    _free(mem_res_two_4);
    debug_heap(stdout, heap);
    _free(mem_res_one_4);
    debug_heap(stdout, heap);
    _free(mem_res_zero_4);
    debug_heap(stdout, heap);


    printf("Test 5: New region is not close to the old");

    void *mem_res_zero_5 = _malloc(8188);
    int *mem_res_one_5 = _malloc(sizeof(int));
    *mem_res_one_5 = 4;
    debug_heap(stdout, heap);
    long long *mem_res_two_5 = _malloc(sizeof(long long ));
    *mem_res_two_5 = 23;
    debug_heap(stdout, heap);

    _free(mem_res_two_5);
    debug_heap(stdout, heap);
    _free(mem_res_one_5);
    debug_heap(stdout, heap);
    _free(mem_res_zero_5);
    debug_heap(stdout, heap);
    return 0;
}
