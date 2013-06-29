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
#include "mls_file.h"
#include "mls_support.h"

char *write_high = "files/write_high.txt";
char *write_low = "files/write_low.txt";
char *read_low = "files/read_low.txt";
char *read_high = "files/read_high.txt";


int test_file_init(void)
{
    unlink(read_low);
    unlink(read_high);

    if (create_file(LVL_LOW, log_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, log_high, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_LOW, read_low, LOW_CONTENTS) != 0) {
        return -1;
    }
    if (create_file(LVL_LOW, write_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, read_high, HIGH_CONTENTS) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, write_high, NULL) != 0) {
        return -1;
    }
    return 0;
}

int test_file_cleanup(void)
{
    return 0;
}


/*****************************************************************************
 * POSIX file system tests
 */

static void test_low_read_low(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "1",
        "--output", log_low,
        "--file", read_low,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_low_read_high(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "2",
        "--output", log_low,
        "--file", read_high,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_low_write_low(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "3",
        "--output", log_low,
        "--file", write_low,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_low_write_high(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "4",
        "--output", log_low,
        "--file", write_high,
        NULL
    };
    fork_to_lvl(LVL_LOW, argv);
}

static void test_high_read_low(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "1",
        "--output", log_high,
        "--file", read_low,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_read_high(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "2",
        "--output", log_high,
        "--file", read_high,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_write_low(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "3",
        "--output", log_high,
        "--file", write_low,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}

static void test_high_write_high(void) 
{
    char * const argv[] = {
        "./mls_file_helper",
        "--test", "4",
        "--output", log_high,
        "--file", write_high,
        NULL
    };
    fork_to_lvl(LVL_HIGH, argv);
}


/*****************************************************************************
 * test structure
 */

CU_TestInfo file_tests[] = {
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
