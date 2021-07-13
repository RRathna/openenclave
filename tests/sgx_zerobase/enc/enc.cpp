// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <sys/mman.h>
#include <iostream>
#include "sgx_zerobase_t.h"

int test_enclave_mmap(uint64_t addr)
{
    void* loc = mmap(
        (void*)addr,
        1,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);

    if (loc != (void*)addr)
        return 1;

    munmap(loc, 1);
    return 0;
}

int test_ecall(const char* message)
{
    if (!message)
        return -1;
    else
        fprintf(stdout, "[enclave] Message from host : %s\n", message);

    int res = -1;
    const char* input = "testing ocall\0";
    OE_TEST(test_ocall(&res, input) == OE_OK);
    if (res != 0)
        fprintf(stderr, "[enclave] ocall failed %d\n", res);

    return res;
}

OE_SET_ENCLAVE_SGX2(
    1,       /* ProductID */
    1,       /* SecurityVersion */
    {0},     /* ExtendedProductID */
    {0},     /* FamilyID */
    true,    /* Debug */
    false,   /* CapturePFGPExceptions */
    false,   /* RequireKSS */
    true,    /* CreateZeroBaseEnclave */
    0x21000, /* StartAddress */
    1024,    /* NumHeapPages */
    1024,    /* NumStackPages */
    4);      /* NumTCS */
