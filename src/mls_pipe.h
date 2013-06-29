/* 
 * A Unit test for Bell-LaPadula enforcement under SELinux-MLS
 *
 * \author Copyright (c) 2013, Mark Gondree
 * \author Copyright (c) 2013, Aaron Flemming
 * \date 2013-2013
 * \copyright BSD 2-Clause License
 *            See http://opensource.org/licenses/BSD-2-Clause
 */
#ifndef __TEST_MLS_PIPE_H__
#define __TEST_MLS_PIPE_H__
#include <CUnit/CUnit.h>

int test_pipe_init(void);
int test_pipe_cleanup(void);
extern CU_TestInfo pipe_tests[];

#endif

