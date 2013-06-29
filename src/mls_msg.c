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
#include "mls_msg.h"
#include "mls_support.h"

char *low_msgq = "/tmp";  // anything unique we can stat
char *high_msgq = "/etc"; // anything unique we can stat

char *low_msg = "abcdef";
char *high_msg = "ABCDEF";


int test_msg_init(void)
{
    if (create_file(LVL_LOW, log_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, log_high, NULL) != 0) {
        return -1;
    }
}

int test_msg_cleanup(void)
{
    return 0;
}

/*****************************************************************************
 * Message Queue tests
 */

static void test_low_read_low(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_LOW, arg3);
}

static void test_low_write_low(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Attaching to write msgq\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_LOW, arg3);

    char * const arg4[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_LOW, arg4);
}


static void test_high_read_high(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_high(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Creating msgq\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "3",
        "--output", log_high,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Attaching to write msgq\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_HIGH, arg3);

    char * const arg4[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_HIGH, arg4);
}


static void test_high_read_low(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "2",
        "--output", log_high,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_read_high(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "4",      // attach to read, expecting failure
        "--output", log_low,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Attaching and reading msgq\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_low(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_high,
        "--file", low_msgq,
        "--data", low_msg,
        NULL
    };
    fprintf(stderr, "Attaching to write msgq\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_write_high(void) 
{
    char * const arg1[] = {
        "./mls_msg_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Creating and writing to msgq\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_msg_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_low,
        "--file", high_msgq,
        "--data", high_msg,
        NULL
    };
    fprintf(stderr, "Attaching to read/write msgq\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_msg_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_msgq,
        NULL
    };
    fprintf(stderr, "Destroying msgq\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


/*****************************************************************************
 * test structure
 */

CU_TestInfo msg_tests[] = {
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