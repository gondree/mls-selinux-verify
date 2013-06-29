/* 
 * A Unit test for Bell-LaPadula enforcement under SELinux-MLS
 *
 * \author Copyright (c) 2013, Mark Gondree
 * \author Copyright (c) 2013, Aaron Flemming
 * \date 2013-2013
 * \copyright BSD 2-Clause License
 *            See http://opensource.org/licenses/BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include <CUnit/CUnit.h>
#include <string.h>
#include "mls_shm.h"
#include "mls_support.h"

char *low_segment = "/low_object";
char *high_segment = "/high_object";

char *low_segment_v = "/tmp";  // anything unique we can stat
char *high_segment_v = "/etc"; // anything unique we can stat

char *low_data = LOW_CONTENTS;
char *high_data = HIGH_CONTENTS;


int test_shm_init(void)
{
    if (create_file(LVL_LOW, log_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, log_high, NULL) != 0) {
        return -1;
    }
    shm_unlink(low_segment);
    shm_unlink(high_segment);
    return 0;
}

int test_shm_cleanup(void)
{
    return 0;
}


/*****************************************************************************
 * POSIX SHM tests
 */

static void test_low_read_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_write_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fprintf(stderr, "There is no pure write for SHM\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg3);

    char * const arg4[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg4);
}


static void test_high_read_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Creating shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "3",
        "--output", log_high,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg3);

    char * const arg4[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg4);
}


static void test_high_read_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_read_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "4",      // attach to read, expecting failure
        "--output", log_low,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_high,
        "--file", low_segment,
        "--data", low_data,
        NULL
    };
    fprintf(stderr, "Attaching to write shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_write_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_low,
        "--file", high_segment,
        "--data", high_data,
        NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fprintf(stderr, "There is no pure write for SHM\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment,
        "--data", "xxx",
        NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


/*****************************************************************************
 * System V SHM tests
 */

static void test_v_low_read_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_v_low_write_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fprintf(stderr, "There is no pure write for SHM\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg3);

    char * const arg4[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg4);
}


static void test_v_high_read_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_v_high_write_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Creating shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "3",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg3);

    char * const arg4[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg4);
}


static void test_v_high_read_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "2",
        "--output", log_high,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_v_low_read_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "4",      // attach to read, expecting failure
        "--output", log_low,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching and reading shm\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_v_high_write_low(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_high,
        "--file", low_segment_v,
        "--data", low_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching to write shm\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_LOW, arg3);
}

static void test_v_low_write_high(void) 
{
    char * const arg1[] = {
        "./mls_shm_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Creating and writing to shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_shm_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_low,
        "--file", high_segment_v,
        "--data", high_data,
        "--sysv", NULL
    };
    fprintf(stderr, "Attaching to read/write shm\n");
    fprintf(stderr, "There is no pure write for SHM\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_shm_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_segment_v,
        "--data", "xxx",
        "--sysv", NULL
    };
    fprintf(stderr, "Destroying shm\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


/*****************************************************************************
 * test structure
 */

CU_TestInfo shm_tests[] = {
    {"test_low_read_low", test_low_read_low},
    {"test_low_read_high", test_low_read_high},
    {"test_low_write_low", test_low_write_low},
    {"test_low_write_high", test_low_write_high},
    {"test_high_read_low", test_high_read_low},
    {"test_high_read_high", test_high_read_high},
    {"test_high_write_low", test_high_write_low},
    {"test_high_write_high", test_high_write_high},
    CU_TEST_INFO_NULL
};

CU_TestInfo shm_v_tests[] = {
    {"test_v_low_read_low", test_v_low_read_low},
    {"test_v_low_read_high", test_v_low_read_high},
    {"test_v_low_write_low", test_v_low_write_low},
    {"test_v_low_write_high", test_v_low_write_high},
    {"test_v_high_read_low", test_v_high_read_low},
    {"test_v_high_read_high", test_v_high_read_high},
    {"test_v_high_write_low", test_v_high_write_low},
    {"test_v_high_write_high", test_v_high_write_high},
    CU_TEST_INFO_NULL
};
