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
#include "mls_sem.h"
#include "mls_support.h"

char *low_sem_key = "/tmp";
char *high_sem_key = "/etc";

char rand_buffer[100];


int test_sem_init(void)
{
    if (create_file(LVL_LOW, log_low, NULL) != 0) {
        return -1;
    }
    if (create_file(LVL_HIGH, log_high, NULL) != 0) {
        return -1;
    }
}

int test_sem_cleanup(void)
{
    return 0;
}

char *get_rand(char *buf, size_t num)
{
	int x = rand() % 100;
	memset(buf, 0, num);
	sprintf(buf, "%d", x);
	return buf;
}

/*****************************************************************************
 * Semaphore
 */

static void test_low_read_low(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_write_low(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "3",
        "--output", log_low,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching to write sem\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "2",
        "--output", log_low,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_LOW, arg3);

    char * const arg4[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_LOW, arg4);
}


static void test_high_read_high(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_high(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Creating shm\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "3",
        "--output", log_high,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching to write sem\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "2",
        "--output", log_high,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_HIGH, arg3);

    char * const arg4[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_HIGH, arg4);
}


static void test_high_read_low(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "2",
        "--output", log_high,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_read_high(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "4",      // attach to read, expecting failure
        "--output", log_low,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching and reading sem\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_HIGH, arg3);
}


static void test_high_write_low(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_LOW, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_high,
        "--file", low_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching to write sem\n");
    fork_to_lvl(LVL_HIGH, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_low,
        "--file", low_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_LOW, arg3);
}


static void test_low_write_high(void) 
{
	char *num = get_rand(rand_buffer, sizeof(rand_buffer));

    char * const arg1[] = {
        "./mls_sem_helper",
        "--test", "1",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Creating and writing to sem\n");
    fork_to_lvl(LVL_HIGH, arg1);

    char * const arg2[] = {
        "./mls_sem_helper",
        "--test", "5",      // attach to write, expecting failure
        "--output", log_low,
        "--file", high_sem_key,
        "--data", num,
        NULL
    };
    fprintf(stderr, "Attaching to write sem\n");
    fork_to_lvl(LVL_LOW, arg2);

    char * const arg3[] = {
        "./mls_sem_helper",
        "--test", "0",
        "--output", log_high,
        "--file", high_sem_key,
        NULL
    };
    fprintf(stderr, "Destroying sem\n");
    fork_to_lvl(LVL_HIGH, arg3);
}

/*****************************************************************************
 * test structure
 */

CU_TestInfo sem_tests[] = {
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