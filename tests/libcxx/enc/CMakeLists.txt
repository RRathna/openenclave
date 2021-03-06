# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

set(EDL_FILE ../libcxx.edl)

add_custom_command(
  OUTPUT libcxx_t.h libcxx_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# helper lib to contain file needed by some tests
add_enclave_library(libcxxtest-support enc.cpp fuzzing.cpp memory_resource.cpp
                    libcxx_t.c)

enclave_compile_options(
  libcxxtest-support
  PRIVATE
  -Wno-error=attributes
  -Wno-error=strict-overflow
  -Wno-error=unused-local-typedefs
  -Wno-error=unused-variable
  -Wno-sign-conversion)

if (ENABLE_FULL_LIBCXX_TESTS)
  enclave_compile_definitions(libcxxtest-support PRIVATE FULL_LIBCXX_TESTS)
endif ()

list(
  APPEND
  CLANG_10_FAILED_TESTS_WITH_SPECULATIVE_LOAD_HARDENING
  std_thread_futures_futures.promise_set_lvalue.pass
  std_thread_futures_futures.promise_set_rvalue.pass
  std_thread_futures_futures.promise_set_value_const.pass
  std_utilities_variant_variant.variant_variant.assign_T.pass)

enclave_link_libraries(libcxxtest-support PRIVATE oelibcxx oeenclave)
enclave_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

enclave_include_directories(libcxxtest-support PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

# Log the build information.
set(BUILD_INFO_FILE "${CMAKE_CURRENT_BINARY_DIR}/build_info.cmake")
file(WRITE "${BUILD_INFO_FILE}"
     "set(LINUX_CXX_COMPILER_ID \"${CMAKE_CXX_COMPILER_ID}\")\n")
file(APPEND "${BUILD_INFO_FILE}"
     "set(LINUX_CXX_COMPILER_VERSION \"${CMAKE_CXX_COMPILER_VERSION}\")\n")

# helper function to create enclave binary
function (add_libcxx_test_enc NAME CXXFILE)
  add_enclave(
    TARGET
    libcxxtest-${NAME}_enc
    UUID
    486dcdcc-f0c6-4bdd-91e0-c7566794f899
    CXX
    # Building the enclave by default when enabling LVI mitigation to
    # test linking against LVI-mitigated libraries.
    ADD_LVI_MITIGATION
    SOURCES
    main.cpp
    libcxx_t.c)

  enclave_include_directories(
    libcxxtest-${NAME}_enc
    PRIVATE
    ..
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/src/filesystem)

  enclave_compile_options(
    libcxxtest-${NAME}_enc
    PRIVATE
    # These are third-party tests, so we don't care about their warnings.
    -Wno-error
    -Wno-unused-function
    -Wno-unused-local-typedef
    -Wno-deprecated-declarations
    # Remove NDEBUG to enable the libcxx testsuite assertions in Release
    -UNDEBUG)

  # Clang does not support variants of operator delete[] taking size_t in C++14 unless
  # -fsized-deallocation is passed explicity.
  # NOTE: This only matters when `ENABLE_FULL_LIBCXX_TESTS=ON`.
  if (NAME MATCHES "sized_delete")
    enclave_compile_options(libcxxtest-${NAME}_enc PRIVATE -fsized-deallocation)
  endif ()

  # Test cases listed in CLANG_10_FAILED_TESTS_WITH_SPECULATIVE_LOAD_HARDENING are failing
  # when speculative load hardening is enabled with Clang. Disable compiler optimizations
  # for those test cases NOTE: This only matters when `ENABLE_FULL_LIBCXX_TESTS=ON`.
  if (NAME IN_LIST CLANG_10_FAILED_TESTS_WITH_SPECULATIVE_LOAD_HARDENING)
    if (WIN32 OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
      set_source_files_properties(main.cpp PROPERTIES COMPILE_FLAGS -O0)
    endif ()
  endif ()

  enclave_compile_definitions(libcxxtest-${NAME}_enc PRIVATE -DWITH_MAIN
                              -D__TEST__="${CXXFILE}")
  enclave_link_libraries(libcxxtest-${NAME}_enc libcxxtest-support)

  if (CXXFILE IN_LIST CXX_17_TEST_LIST)
    set_enclave_property(TARGET libcxxtest-${NAME}_enc PROPERTY CXX_STANDARD 17)
  endif ()

  if (WIN32)
    maybe_build_using_clangw(libcxxtest-${NAME}_enc)

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX
        "${CMAKE_STATIC_LIBRARY_PREFIX}"
        PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX
        "${CMAKE_STATIC_LIBRARY_SUFFIX}"
        PARENT_SCOPE)

    # Propagate library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY
        "${CMAKE_C_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY
        "${CMAKE_CXX_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)

    # Propagate linker variables
    set(CMAKE_EXECUTABLE_SUFFIX
        "${CMAKE_EXECUTABLE_SUFFIX}"
        PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES
        "${CMAKE_C_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE
        "${CMAKE_C_LINK_EXECUTABLE}"
        PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES
        "${CMAKE_CXX_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE
        "${CMAKE_CXX_LINK_EXECUTABLE}"
        PARENT_SCOPE)

    # Propagate cpmpiler variables
    set(CMAKE_C_COMPILE_OBJECT
        "${CMAKE_C_COMPILE_OBJECT}"
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT
        "${CMAKE_CXX_COMPILE_OBJECT}"
        PARENT_SCOPE)
  endif ()
endfunction (add_libcxx_test_enc)

# Iterate over the supported tests and create a binary for each.
if (ENABLE_FULL_LIBCXX_TESTS)
  file(STRINGS "../tests.supported" alltests)
else ()
  file(STRINGS "../tests.supported.default" alltests)
endif ()

foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

  # The allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds
  if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass"
      OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    if (CMAKE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
      continue()
    endif ()
  endif ()

  # The following test fails when built with clang, see #830 -- Skipping this test in clang
  if ("${name}" MATCHES
      "array_sized_delete_array_calls_unsized_delete_array.pass")
    if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
      continue()
    endif ()
  endif ()

  add_libcxx_test_enc("${name}" "${testcase}")
endforeach (testcase)
