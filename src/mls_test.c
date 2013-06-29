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
#include <sys/types.h>
#include <sys/wait.h>
#include <CUnit/Basic.h>
#include "mls_file.h"
#include "mls_shm.h"
#include "mls_msg.h"
#include "mls_sem.h"
#include "mls_pipe.h"

int main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();

    // Add suites to registry
    CU_SuiteInfo suites[] = {
      {"file", test_file_init, test_file_cleanup, file_tests},
      {"posix shm", test_shm_init, test_shm_cleanup, shm_tests},
      {"sys v shm", test_shm_init, test_shm_cleanup, shm_v_tests},
      {"msg queue", test_msg_init, test_msg_cleanup, msg_tests},
      {"sem", test_sem_init, test_sem_cleanup, sem_tests},
      //{"pipes", test_pipe_init, test_pipe_cleanup, pipe_tests},
      CU_SUITE_INFO_NULL
    };

    // Register and prepare the tests/suites
    CU_register_suites(suites);
    CU_basic_set_mode(CU_BRM_VERBOSE);
    
    // Run all of the  tests
    CU_basic_run_tests();

    // Clear the test registry
    CU_cleanup_registry();

    // Get and then return the error code from running the tests
    return CU_get_error();
}

