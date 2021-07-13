// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <sys/mman.h>
#include <iostream>
#include <vector>
#include "sgx_zerobase_u.h"

const char* message = "Hello world from Host\n\0";

int test_ocall(const char* message)
{
    if (!message)
        return -1;

    fprintf(stdout, "[host] Message from enclave : %s\n", message);

    return 0;
}

int test_host_mmap(uint64_t addr)
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

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 1: Create 0-base enclave in sim-mode\n"
        "Expected result : OE_INVALID_PARAMETER\n");
    result = oe_create_sgx_zerobase_enclave(
        argv[1],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_SIMULATE,
        NULL,
        0,
        &enclave);

    if (result != OE_INVALID_PARAMETER)
    {
        fprintf(
            stderr,
            "Unexpected error when creating enclave in sim-mode, result=%d\n",
            result);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 2: Create 0-base enclave\n"
        "Expected result : OE_OK\n");
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_sgx_zerobase_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create 0-base enclave, result=%d\n", result);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 3: Test ecall, ocall on 0-base enclave\n"
        "Expected result : OE_OK\n");
    const char* input = "testing ecall\0";
    int res = -1;
    OE_TEST(test_ecall(enclave, &res, input) == OE_OK);

    if (res != 0)
    {
        fprintf(stderr, "[host]: ecall/ocall failed %d\n", res);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 4: Check host access to [/proc/sys/vm/mmap_min_addr, "
        "elrange->image_start_address]\n"
        "Expected result : successful\n");

    uint64_t addr = 0x15000;

    if (test_host_mmap(addr) != 0)
    {
        fprintf(stderr, "host mmap at address %lx failed\n", addr);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 5: Check enclave access to [enclave_image_start_address, "
        "enclave_image_end_address]\n"
        "Expected result : successful\n");

    addr = 0x35000;
    OE_TEST(test_enclave_mmap(enclave, &res, addr) == OE_OK);
    if (res != 0)
    {
        fprintf(stderr, "enclave mmap at address %lx failed\n", addr);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 6: Check host access to 0x0\n"
        "Expected result : failed\n");

    addr = 0x0;

    if (!test_host_mmap(addr))
    {
        fprintf(stderr, "host mmap at address %lx failed\n", addr);
    }
    else
        return 1;

    OE_TEST(test_enclave_mmap(enclave, &res, addr) == OE_OK);
    if (res != 0)
    {
        fprintf(stderr, "enclave mmap at address %lx failed\n", addr);
        return 1;
    }

    if (oe_terminate_enclave(enclave) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave(): failed: result=%d\n", result);
        return 1;
    }

    printf("=== passed all tests (sgx_zerobase)\n");

    return 0;
}
