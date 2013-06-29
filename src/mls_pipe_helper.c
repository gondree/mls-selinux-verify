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
#include <fcntl.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include "mls_file.h"
#include "mls_support.h"


void read_low(int level, const char *fname)
{
    int fd = -1;
    static char buf[10];
    int status = -1;

    printf("%s(..., %s)\n", __func__, fname);
    fflush(stdout);

    fd = open(fname, O_RDONLY);
    if (fd == -1) {
        printf("open(%s)\n", fname);
        perror("open failed");

    }
    fflush(stdout);
    if (level == AT_LOW) {
        // low should be able to read low
        assert(fd != -1);
    } else if (level == AT_HIGH) {
        // high should be able to read low
        assert(fd != -1);
    } else {
        assert(0 != 0);
    }
	printf("got here"); fflush(stdout);
    if (fd != -1) {
        status = read(fd, buf, sizeof(buf));
        printf("File contains: %s\n", LOW_CONTENTS);
        printf("We read %d:  %s\n", status, buf);
        
        if (strcmp(buf, LOW_CONTENTS) != 0) {
            assert(0 != 1);
        } else {
            printf("PASS\n");
        }
    }
    fflush(stdout);
    if (fd != -1) {
        close(fd);
    }
}


void read_high(int level, const char *fname)
{
    int fd = -1;
    static char buf[10];
    int status;

    printf("%s(..., %s)\n", __func__, fname);

    fd = open(fname, O_RDONLY);
    if (fd == -1) {
        printf("open(%s)\n", fname);
        perror("open failed");

    }
    if (level == AT_LOW) {
        // low should not be able to read high
        assert(fd == -1);
        printf("PASS\n");
    } else if (level == AT_HIGH) {
        // high should be able to read high
        assert(fd != -1);
    } else {
        assert(0 != 1);
    }

    if (fd != -1) {
        status = read(fd, buf, sizeof(buf));
        printf("File contains: %s\n", HIGH_CONTENTS);
        printf("We read %d:  %s\n", status, buf);
        
        if (strcmp(buf, HIGH_CONTENTS) != 0) {
            assert(0 != 1);
        } else {
            printf("PASS\n");
        }
    }
    if (fd != -1) {
        close(fd);
    }
}


void write_low(int level, const char *fname)
{ 
    int fd = -1;
    int status;
    time_t t;

    printf("%s(..., %s)\n", __func__, fname);
    time(&t);

    fd = open(fname, O_WRONLY);
    if (fd == -1) {
        printf("open(%s)\n", fname);
        perror("open failed");

    }
    if (level == AT_LOW) {
        // low should be able to write low
        assert(fd != -1);
    } else if (level == AT_HIGH) {
        // high should not be able to write low
        assert(fd == -1);
        printf("PASS\n");
    } else {
        assert(0 != 1);
    }

    if (fd != -1) {
        status = write(fd, LOW_CONTENTS, sizeof(LOW_CONTENTS));
        printf("Write at %s\n", (level == AT_LOW) ? LVL_LOW : LVL_HIGH);
        printf("We wrote %d chars\n", status);
        assert(status > 0);
        printf("PASS\n");
    }
    if (fd != -1) {
        close(fd);
    }
}


void write_high(int level, const char *fname)
{
    int fd = -1;
    int status;
    time_t t;

    printf("%s(..., %s)\n", __func__, fname);
    time(&t);

    fd = open(fname, O_WRONLY);
    if (fd == -1) {
        printf("open(%s)\n", fname);
        perror("open failed");

    }
    if (level == AT_LOW) {
        if (fd != -1) {
            // This is okay under Bell-LaPadula model
            // but most real systems don't implement it
            printf("Wow, neat -- low can write to high\n");
        }
    } else if (level == AT_HIGH) {
        // high should be able to write high
        assert(fd != -1);
        printf("PASS\n");
    } else {
        assert(0 != 1);
    }

    if (fd != -1) {
        status = write(fd, HIGH_CONTENTS, sizeof(HIGH_CONTENTS));
        printf("Write at %s\n", (level == AT_LOW) ? LVL_LOW : LVL_HIGH);
        printf("We wrote %d chars\n", status);
        assert(status > 0);
        printf("PASS\n");
    }
    if (fd != -1) {
        close(fd);
    }
}


int main(int argc, char* argv[])
{
    int opt, option_index;
    int test_num  = -1;
    int level = -1;
    context_t ctx = NULL;
    security_context_t ctx_check = NULL;
    char *path = NULL;
    char *log_path = NULL;
    time_t t;

    static struct option long_options[] = {
      {"output",  required_argument, 0, 'o'},
      {"test",    required_argument, 0, 't'},
      {"file",    required_argument, 0, 'f'},
      {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "o:t:f:",
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
        case 1:
            read_low(level, path);
            break;
        case 2:
            read_high(level, path);
            break;
        case 3:
            write_low(level, path);
            break;
        case 4:
            write_high(level, path);
            break;
        default:
            printf("invalid test chosen\n");
            exit(-1);
            break;
    }
    return 0;
}

