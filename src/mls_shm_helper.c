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
#include <sys/shm.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include "mls_shm.h"
#include "mls_support.h"

/*****************************************************************************
 * System V shared memory logic
 */


int create_shm_v(struct shared_space_t **ptr, const char *path, int fail)
{
    int status = 0;
    key_t key;
    struct shared_space_t *segptr = NULL;
    int id = -1;

    printf("%s(..., %s)\n", __func__, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    id = shmget(key, MEM_SIZE, IPC_CREAT | MODE_RWX);
    if (id == -1) {
        perror("shmget failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("shmget successful\n");
        if (fail) exit(-1);
    }

    segptr = shmat(id, NULL, 0);
    if (segptr == NULL) {
        perror("shmat failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("shmat successful\n");
        if (fail) exit(-1);
    }

    // Initialize the data structure in memory
    segptr->counter = 0;
    memset(segptr->data, 0, MAX_STRING);
    segptr->state = STATE_READY;
    printf("Initialization complete\n");
    *ptr = segptr;
    return id;
}

int attach_shm_v(int oflag, struct shared_space_t **ptr, 
                 const char *path, int fail)
{
    struct shared_space_t *segptr = NULL;
    int status = 0;
    int i = 0;
    int id = -1;
    char * smode = (oflag == O_RDONLY) ? "read" : "write";
    mode_t mode = (oflag == O_RDONLY) ? SHM_R : SHM_W;
    int shmflg = (oflag == O_RDONLY) ? SHM_RDONLY : 0;
    key_t key;

    printf("%s(%s, ..., %s)\n", __func__, smode, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    while ((i < MAX_TRIES) && (id < 0)) {
        id = shmget(key, MEM_SIZE, mode);
        i++;

        if (id < 0) {
            perror("shmget failed");
            printf("Waiting %d seconds to try again.\n", WAIT_TIME);
            sleep(WAIT_TIME);
        }
    }

    if (id < 0) {
        printf("Gave up.\n");
        if (!fail) exit(-1);
        return -1;
    } else {
        printf("shmget successful\n");
        if (fail) exit(-1);
    }

    segptr = shmat(id, NULL, shmflg);
    if (id == -1) {
        perror("shmat failed");
        if (!fail) exit(-1);
        return 0;
    } else {
        printf("shmat successful\n");
        if (fail) exit(-1);
        *ptr = segptr;
    }

    return id;
}

int close_shm_v(const char *path)
{
    int status = 0;
    key_t key;
    void *segptr = NULL;
    int id = -1;

    printf("%s(..., %s)\n", __func__, path);

    key = ftok(path, TEST_KEY_ID);
    if (key == (key_t) -1) {
        perror("ftok failed");
        exit(-1);
    }

    // getting
    id = shmget(key, MEM_SIZE, SHM_R);
    if (id == -1) {
        perror("shmget failed");
        exit(-1);
    } else {
        printf("shmget successful\n");
    }

    // ataching
    segptr = shmat(id, NULL, 0);
    if (id == -1) {
        perror("shmat failed");
        exit(-1);
    } else {
        printf("shmat successful\n");
    }

    // marking shm segment for deletion
    status = shmctl(id, IPC_RMID, NULL);
    if (status == -1) {
        perror("shmctl failed");
        exit(-1);
    } else {
        printf("shmctl successful\n");
    }

    // detaching shm segment to delete it
    status = shmdt(segptr);
    if (status == -1) {
        perror("shmdt failed");
        exit(-1);
    } else {
        printf("shmdt successful\n");
    }

    return 0;
}


/*****************************************************************************
 * POSIX shared memory logic
 */


int create_shm(struct shared_space_t **ptr, const char *path, int fail)
{
    struct shared_space_t *segptr = NULL;
    int status= 0;
    int fd = -1;

    printf("%s(..., %s)\n", __func__, path);

    // Create a shared memory object and truncate it.
    fd = shm_open(path, O_CREAT | O_RDWR | O_TRUNC, MODE_RWX);
    if (fd < 0) {
        perror("shm_open failed");
        if (!fail) exit(-1);
    } else {
        printf("shm_open successful\n");
        if (fail) exit(-1);
    }

    // Set the size of the shared memory object
    status = ftruncate(fd, MEM_SIZE);
    if (status != 0) {
        perror("ftruncate failed");
        if (!fail) exit(-1);
    } else {
        printf("ftruncate successful\n");
        if (fail) exit(-1);
    }

    // Map the object into the process memory space
    segptr = (struct shared_space_t *) 
        mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (segptr == MAP_FAILED) {
        perror("mmap failed");
        if (!fail) exit(-1);
    } else {
        printf("mmap successful\n");
        if (fail) exit(-1);
    }

    // Initialize the data structure in memory
    segptr->counter = 0;
    memset(segptr->data, 0, MAX_STRING);
    segptr->state = STATE_READY;
    printf("Initialization complete\n");
    *ptr = segptr;
    return fd;
}


int attach_shm(int oflag, struct shared_space_t **ptr, 
               const char *path, int fail)
{
    struct shared_space_t *segptr = NULL;
    int status= 0;
    int i = 0;
    int fd = -1;
    char * smode = (oflag == O_RDONLY) ? "read" : "write";
    int prot = (oflag == O_RDONLY) ? PROT_READ : PROT_WRITE;
    mode_t mode = (oflag == O_RDONLY) ? MODE_R : MODE_W;

    printf("%s(%s, ..., %s)\n", __func__, smode, path);

    while ((i < MAX_TRIES) && (fd < 0)) {
        fd = shm_open(path, oflag, mode);
        i++;

        if (fd < 0) {
            perror("shm_open failed");
            printf("Waiting %d seconds to try again.\n", WAIT_TIME);
            sleep(WAIT_TIME);
        }
    }

    if (fd < 0) {
        printf("Gave up.\n");
        if (!fail) exit(-1);
        return -1;
    } else {
        printf("shm_open successful\n");
        if (fail) exit(-1);
    }

    // Map the object into the process memory space
    segptr = (struct shared_space_t *) 
        mmap(NULL, MEM_SIZE, prot, MAP_SHARED, fd, 0);
    if (segptr == MAP_FAILED) {
        perror("mmap failed");
        if (!fail) exit(-1);
    } else {
        printf("mmap successful\n");
        if (fail) exit(-1);
        *ptr = segptr;
    }

    return fd;
}


int close_shm(const char *path)
{
    int status= 0;

    printf("%s(..., %s)\n", __func__, path);

    status = shm_unlink(path);
    if (status != 0) {
        perror("Failed to delete shared memory");
        exit(-1);
    }
    return 0;
}

/*****************************************************************************
 * generic functions
 */

int write_shm(struct shared_space_t *segptr, const char* data, int fail)
{
    char *status = NULL;

    printf("%s(..., %s)\n", __func__, data);

    if (segptr == MAP_FAILED) {
        printf("Invalid program state\n");
        return 0;
    }
    printf("State of shm (%d: %s)\n", segptr->counter, segptr->data);
    
    // Pass data
    segptr->state = STATE_WRITING;
    status = strcpy(segptr->data, data);

    if (segptr->data != status) {
        perror("strcpy");
        if (!fail) exit(-1);
        return -1;
    } else {
        printf("write successful\n");
        if (fail) exit(-1);
    }

    segptr->counter = ++(segptr->counter);
    segptr->state = STATE_DONE;
    printf("State of shm (%d: %s)\n", segptr->counter, segptr->data);
    return 0;
}


int read_shm(struct shared_space_t *segptr, const char* data, int fail)
{
    int status;
    int done = 0;
    int tries = 0;

    printf("%s(..., %s)\n", __func__, data);

    if (segptr == NULL) {
        printf("Invalid program state\n");
        return 0;
    }

    while ((tries <= MAX_TRIES) && (!done)) {
        switch (segptr->state) {
            case STATE_DONE:
                status = strncmp(segptr->data, data, strlen(data));
                printf("State of shm (%d: %s)\n",
                       segptr->counter, segptr->data);
                if (status != 0) {
                    printf("Data did not look as expected");
                    exit(-1);
                }
                done = 1;
                break;
            case STATE_READY:
                printf("Creator has not yet written.\n");
                break;
            case STATE_WRITING:
                printf("Creator is writing.\n");
                break;
            default:
                printf("Corrupted segment state: exiting\n");
                exit(-1);
                break;
        }
        sleep(WAIT_TIME);
        ++tries;
    }
    if (tries > MAX_TRIES) {
        printf("Giving up.\n");
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
    struct shared_space_t *segptr;
    int opt, option_index;
    int test_num = -1;
    int level = -1;
    int fd = -1;
    int system_v = 0;
    char *path = NULL;
    char *log_path = NULL;
    char *data = NULL;
    time_t t;

    static struct option long_options[] = {
      {"output",  required_argument, 0, 'o'},
      {"test",    required_argument, 0, 't'},
      {"file",    required_argument, 0, 'f'},
      {"data",    required_argument, 0, 'd'},
      {"sysv",    no_argument,       0, 'v'},
      {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "o:t:f:d:v",
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
            case 'v':
                system_v = 1;
                printf("using System V shm.\n");
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
            printf("deleting shm\n");
            if (system_v) {
                close_shm_v(path);
            } else {
                close_shm(path);
            }
            break;
        case 1:
            printf("creating and initializing shm\n");
            if (system_v) {
                fd = create_shm_v(&segptr, path, 0);
                write_shm(segptr, data, 0);
            } else {
                fd = create_shm(&segptr, path, 0);
                write_shm(segptr, data, 0);
                if (fd > -1) close(fd);
            }
            break;
        case 2:
            printf("attaching and reading shm\n");
            if (system_v) {
                fd = attach_shm_v(O_RDONLY, &segptr, path, 0);
                read_shm(segptr, data, 0);
            } else {
                fd = attach_shm(O_RDONLY, &segptr, path, 0);
                read_shm(segptr, data, 0);
                if (fd > -1) close(fd);
            }
            break;
        case 3:
            printf("attaching and writing shm\n");
            if (system_v) {
                fd = attach_shm_v(O_RDWR, &segptr, path, 0);
                write_shm(segptr, data, 0);
            } else {
                fd = attach_shm(O_RDWR, &segptr, path, 0);
                write_shm(segptr, data, 0);
                if (fd > -1) close(fd);
            }
            break;
        case 4:
            printf("attaching for read, expecting failure\n");
            if (system_v) {
                fd = attach_shm_v(O_RDONLY, &segptr, path, 1);
            } else {
                fd = attach_shm(O_RDONLY, &segptr, path, 1);
                if (fd > -1) close(fd);
            }
            break;
        case 5:
            printf("attaching for write, expecting failure\n");
            if (system_v) {
                fd = attach_shm_v(O_RDWR, &segptr, path, 1);
            } else {
                fd = attach_shm(O_RDWR, &segptr, path, 1);
                if (fd > -1) close(fd);
            }
            break;
        default:
            printf("invalid test chosen\n");
            exit(-1);
            break;
    }
    return 0;
}

