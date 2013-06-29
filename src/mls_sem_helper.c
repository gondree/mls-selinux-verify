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
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>     // for the O_ constants
#include <sys/ipc.h>
#include <sys/sem.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include "mls_sem.h"
#include "mls_support.h"


union semun
{
    int val;
    struct semid_ds *buf;
    ushort  *array;
};

int create_sem(const char *path, int fail)
{
    int status = 0;
    key_t key;
    int id = -1;
    union semun sem_union;
    sem_union.val = 0;

    printf("%s(..., %s)\n", __func__, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    id = semget(key, 1, IPC_CREAT | MODE_RWX);
    if (id == -1) {
        perror("semget failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("semget successful\n");
        if (fail) exit(-1);
    }

    status = semctl(id, 0, SETVAL, sem_union);
    if (status == -1) {
        perror("semctl failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("semctl successful\n");
        if (fail) exit(-1);
    }
    printf("Initialization complete\n");
    return id;
}

int attach_sem(int oflag, const char *path, int fail)
{
    int status = 0;
    int i = 0;
    int id = -1;
    char *smode = (oflag == O_RDONLY) ? "read" : "write";
    int mode = (oflag == O_RDONLY) ? MODE_R : MODE_W;
    key_t key;

    printf("%s(%s, ..., %s)\n", __func__, smode, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    while ((i < MAX_TRIES) && (id < 0)) {
        id = semget(key, 1, mode);
        i++;

        if (id < 0) {
            perror("semget failed");
            printf("Waiting %d seconds to try again.\n", WAIT_TIME);
            sleep(WAIT_TIME);
        }
    }

    if (id < 0) {
        printf("Gave up.\n");
        if (!fail) exit(-1);
        return -1;
    } else {
        printf("semget successful\n");
        if (fail) exit(-1);
    }
    return id;
}

int close_sem(const char *path, int fail)
{
    int status = 0;
    key_t key;
    int id = -1;

    printf("%s(..., %s)\n", __func__, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    // getting
    id = semget(key, 1, MODE_R);
    if (id == -1) {
        perror("semget failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("semget successful\n");
        if (fail) exit(-1);
    }

    // marking shm segment for deletion
    status = semctl(id, 0, IPC_RMID);
    if (status == -1) {
        perror("semctl failed");
        exit(-1);
    } else {
        printf("semctl successful\n");
    }
    return 0;
}

int write_sem(int id, const char* data, int fail)
{
    int status = -1;
    union semun sem_union;
    sem_union.val = atoi(data);

    printf("%s(..., %s)\n", __func__, data);
    
    status = semctl(id, 0, SETVAL, sem_union);
    if (status == -1) {
        perror("semctl SETVAL failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("semctl SETVAL successful\n");
        if (fail) exit(-1);
    }
    return 0;
}

int read_sem(int id, const char* data, int fail)
{
    int status = -1;
    int val = atoi(data);

    printf("%s(..., %s)\n", __func__, data);

    status = semctl(id, 0, GETVAL);
    if (status == -1) {
        perror("semctl GETVAL failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("semctl GETVAL successful: %d\n", status);
        if (fail) exit(-1);
    }
    if (status != val) {
        printf("Data did not look as expected: %d / %d", status, val);
        if (!fail) exit(-1);
    }
    return 0;
}


/*****************************************************************************
 * Main
 */

int main(int argc, char* argv[])
{
    context_t ctx = NULL;
    security_context_t ctx_check = NULL;
    int opt, option_index;
    int test_num = -1;
    int level = -1;
    int fd = -1;
    char *path = NULL;
    char *log_path = NULL;
    char *data = NULL;
    time_t t;

    static struct option long_options[] = {
      {"output",  required_argument, 0, 'o'},
      {"test",    required_argument, 0, 't'},
      {"file",    required_argument, 0, 'f'},
      {"data",    required_argument, 0, 'd'},
      {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "o:t:f:d:",
                              long_options, &option_index)) != -1)
    {
        switch (opt) {            
            case 'o':
                log_path = optarg;
                if (freopen(log_path, "a+", stdout) == NULL) {
                    exit(-1);
                }
                if (freopen(log_path, "a+", stderr) == NULL) {
                    exit(-1);
                }
                break;
            case 't':
                test_num = atoi(optarg);
                break;
            case 'f':
                path = optarg;
                break;
            case 'd':
                data = optarg;
                break;
            default:
                printf("bad argument.\n");
                exit(-1);
            }
    }     

    if (test_num == -1) {
        printf("no test specified.\n");
        exit(-1);
    } else if (path == NULL) {
        printf("no path specified.\n");
        exit(-1);
    }

    time(&t);
    printf("\n%s", ctime(&t));
    getcon(&ctx_check);
    printf("Context: '%s'\n", ctx_check); 
    ctx = context_new(ctx_check);
    const char *range = context_range_get(ctx);

    if (strncmp(LVL_HIGH"-", range, sizeof(LVL_HIGH"-")-1) == 0) {
        level = AT_HIGH;
        printf("process is at high\n");
    } else if (strncmp(LVL_LOW"-", range, sizeof(LVL_LOW"-")-1) == 0) {
        level = AT_LOW;
        printf("process is at low\n");
    } else {
        printf("unexpected level\n");
        exit(-1);
    }

    fflush(stdout); fflush(stderr);

    switch(test_num) {
        case 0: 
            printf("deleting sem\n");
            close_sem(path, 0);
            break;
        case 1:
            printf("creating and initializing sem\n");
            fd = create_sem(path, 0);
            if (data) write_sem(fd, data, 0);
            break;
        case 2:
            printf("attaching and reading sem\n");
            fd = attach_sem(O_RDONLY, path, 0);
            if (data) read_sem(fd, data, 0);
            break;
        case 3:
            printf("attaching and writing sem\n");
            fd = attach_sem(O_RDWR, path, 0);
            if (data) write_sem(fd, data, 0);
            break;
        case 4:
            printf("attaching for read, expecting failure\n");
            fd = attach_sem(O_RDONLY, path, 1);
            break;
        case 5:
            printf("attaching for write, expecting failure\n");
            fd = attach_sem(O_RDWR, path, 1);
            break;
        default:
            printf("invalid test chosen\n");
            exit(-1);
            break;
    }
    return 0;
}

