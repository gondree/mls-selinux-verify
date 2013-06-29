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
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include <CUnit/CUnit.h>
#include <string.h>
#include "mls_sem.h"
#include "mls_support.h"

char *low_pipe = "low_fifo";
char *high_pipe = "high_fifo";


int test_pipe_init(void)
{
    if (create_file(LVL_LOW, log_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, log_high, NULL) != 0) {
        return -1;
    }
    unlink(low_pipe);
    unlink(high_pipe);
    if (create_fifo(LVL_LOW, low_pipe) != 0) {
        return -1;
    }
    if (create_fifo(LVL_HIGH, high_pipe) != 0) {
        return -1;
    }
}

int test_pipe_cleanup(void)
{
    return 0;
}


/*****************************************************************************
 * Pipes
 */

static void test_low_read_low(void) 
{
    char * const argv1[] = {
        "./mls_pipe_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_pipe,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv1);
    char * const argv2[] = {
        "./mls_pipe_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_pipe,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv2);
}

static void test_low_read_high(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "2",
        "--output", log_low,
        "--file", high_pipe,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_low_write_low(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_pipe,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_low_write_high(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "4",
        "--output", log_low,
        "--file", high_pipe,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_high_read_low(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "1",
        "--output", log_high,
        "--file", low_pipe,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_read_high(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_pipe,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_write_low(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "3",
        "--output", log_high,
        "--file", low_pipe,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_write_high(void) 
{
    char * const argv[] = {
        "./mls_pipe_helper",
        "--test", "4",
        "--output", log_high,
        "--file", high_pipe,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}


/*****************************************************************************
 * test structure
 */

CU_TestInfo pipe_tests[] = {
    {"test_low_read_low", test_low_read_low},
    //{"test_low_read_high", test_low_read_high},
    //{"test_low_write_low", test_low_write_low},
    //{"test_low_write_high", test_low_write_high},
    //{"test_high_read_low", test_high_read_low},
    //{"test_high_read_high", test_high_read_high},
    //{"test_high_write_low", test_high_write_low},
    //{"test_high_write_high", test_high_write_high},
    CU_TEST_INFO_NULL
};