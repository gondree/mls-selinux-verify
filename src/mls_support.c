/* 
 * A Unit test for Bell-LaPadula enforcement under SELinux-MLS
 *
 * \author Copyright (c) 2013, Mark Gondree
 * \date 2013-2013
 * \copyright BSD 2-Clause License
 *            See http://opensource.org/licenses/BSD-2-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <selinux/selinux.h>
#include <selinux/context.h> // for context-mangling functions
#include <CUnit/CUnit.h>
#include "mls_support.h"

/**
 * Construct from the current range and specified desired level a resulting
 * range. If the specified level is a range, return that. If it is not, then
 * construct a range with level as the sensitivity and clearance of the current
 * context.
 *
 * newlevel - the level specified on the command line
 * range    - the range in the current context
 *
 * Returns malloc'd memory
 */
char *build_new_range(const char *newlevel, const char *range)
{
    char *newrangep = NULL;
    const char *tmpptr;
    size_t len;

    // a missing or empty string
    if (!range || !strlen(range) || !newlevel || !strlen(newlevel))
        return NULL;

    // if the newlevel is actually a range - just use that
    if (strchr(newlevel, '-')) {
        newrangep = strdup(newlevel);
        return newrangep;
    }

    // look for MLS range in current context
    tmpptr = strchr(range, '-');
    if (tmpptr) {
        /* we are inserting into a ranged MLS context */
        len = strlen(newlevel) + 1 + strlen(tmpptr + 1) + 1;
        newrangep = (char *)malloc(len);
        if (!newrangep)
            return NULL;
        snprintf(newrangep, len, "%s-%s", newlevel, tmpptr + 1);
    } else {
        // we are inserting into a currently non-ranged MLS context
        if (!strcmp(newlevel, range)) {
            newrangep = strdup(range);
        } else {
            len = strlen(newlevel) + 1 + strlen(range) + 1;
            newrangep = (char *)malloc(len);
            if (!newrangep)
                return NULL;
            snprintf(newrangep, len, "%s-%s", newlevel, range);
        }
    }

    return newrangep;
}


/*
 * Change context to a new level
 */
void chcon_to_level(const char *level_s)
{
    security_context_t new_ctx = NULL;
    security_context_t old_ctx = NULL;
    context_t ctx = NULL;
    char *new_range = NULL;
    int status = 0;

    // Build new context, from old context
    status = getcon(&old_ctx);
    CU_ASSERT_EQUAL(status, 0);
    fprintf(stderr, "Current process context: '%s'\n", old_ctx);
    
    ctx = context_new(old_ctx);
    CU_ASSERT_PTR_NOT_NULL(ctx);
    
    new_range = build_new_range(level_s, context_range_get(ctx));
    CU_ASSERT_PTR_NOT_NULL(new_range);
    status = context_range_set(ctx, new_range);
    CU_ASSERT_EQUAL(status, 0);
    
    // Change new context to user_u equivalent
    status = context_user_set(ctx, "mls_test_u");
    CU_ASSERT_EQUAL(status, 0);
    status = context_role_set(ctx, "user_r");
    CU_ASSERT_EQUAL(status, 0);
    status = context_type_set(ctx, "user_t");
    CU_ASSERT_EQUAL(status, 0);
    
    fprintf(stderr, "New range: %s\n", context_range_get(ctx));
    new_ctx = context_str(ctx);     
    fprintf(stderr, "New process context: '%s'\n", new_ctx);
    CU_ASSERT_PTR_NOT_NULL(new_ctx);

    // change context for exec
    status = setexeccon(new_ctx);
    CU_ASSERT_EQUAL(status, 0);

    freecon(new_ctx);
    freecon(old_ctx);
    free(new_range);
}


/*
 * Create a file at a new level
 */
int create_file(const char *lvl, const char *path, const char *data)
{
    security_context_t new_ctx = NULL;
    security_context_t old_ctx = NULL;
    context_t ctx = NULL;
    char *new_range = NULL;
    int status = 0;
    FILE *file = NULL;

    status = getcon(&old_ctx);
    if (status != 0) return -1;
    ctx = context_new(old_ctx);
    if (ctx == NULL) return -1;

    new_range = build_new_range(lvl, context_range_get(ctx));
    if (new_range == NULL) return -1;
    status = context_range_set(ctx, new_range);
    if (status != 0) return -1;

    status = context_user_set(ctx, "mls_test_u");
    if (status != 0) return -1;
    status = context_role_set(ctx, "object_r");
    if (status != 0) return -1;
    status = context_type_set(ctx, "user_home_t");
    if (status != 0) return -1;

    new_ctx = context_str(ctx);
    fprintf(stderr, "writing file '%s' with context '%s'\n", path, new_ctx);
    if (ctx == NULL) return -1;
    status = setfscreatecon(new_ctx);
    if (status != 0) return -1;

    file = fopen(path, "a+");
    if (file == NULL) {
        perror("fopen failed");
        return -1;
    }
    fprintf(stderr, "opened file '%s' with context '%s'\n", path, new_ctx);

    if (data != NULL) {
        status = fprintf(file, "%s", data);
        if (status != strlen(data)) {
            fprintf(stderr, "fprintf(): %d (%s)\n", errno, strerror(errno));
            return -1;
        }
    }
    fclose(file);
    freecon(new_ctx);
    freecon(old_ctx);
    free(new_range);
    return 0;
}

/*
 * Create a FIFO at a new level
 */
int create_fifo(const char *lvl, const char *path)
{
    security_context_t new_ctx = NULL;
    security_context_t old_ctx = NULL;
    context_t ctx = NULL;
    char *new_range = NULL;
    int status = 0;

    status = getcon(&old_ctx);
    if (status != 0) return -1;
    ctx = context_new(old_ctx);
    if (ctx == NULL) return -1;

    new_range = build_new_range(lvl, context_range_get(ctx));
    if (new_range == NULL) return -1;
    status = context_range_set(ctx, new_range);
    if (status != 0) return -1;

    status = context_user_set(ctx, "mls_test_u");
    if (status != 0) return -1;
    status = context_role_set(ctx, "object_r");
    if (status != 0) return -1;
    status = context_type_set(ctx, "user_home_t");
    if (status != 0) return -1;

    new_ctx = context_str(ctx);
    fprintf(stderr, "writing file '%s' with context '%s'\n", path, new_ctx);
    if (ctx == NULL) return -1;
    status = setfscreatecon(new_ctx);
    if (status != 0) return -1;

    status = mkfifo(path, S_IRWXU|S_IRWXG|S_IRWXO);
    if (status != 0) {
        perror("mkfifo failed");
        return -1;
    }
    fprintf(stderr, "created file '%s' with context '%s'\n", path, new_ctx);

    freecon(new_ctx);
    freecon(old_ctx);
    free(new_range);
    return 0;
}

/*
 * Exec a process at a new level
 */
int fork_to_lvl(const char *lvl, char * const argv[])
{
    pid_t pid;
    int status = 0;
    int i;

    pid = fork();
    switch(pid) 
    {
        case -1:
            perror("fork failed");
            break;
        case 0:
            chcon_to_level(lvl);
            fprintf(stderr, "Running: ");
            for(i=0; argv[i] != NULL; i++) {
                fprintf(stderr, "%s ", argv[i]);
            }
            fprintf(stderr, "\n");
            execvp(argv[0], argv);
            fprintf(stderr, "got past exec()\n");
            perror("exec failed");
            CU_FAIL("got past exec");
            exit(-1);
            break;
        default:
            fprintf(stderr, "child pid is %i\n", pid);
            do {
                pid = waitpid(pid, &status, 0);
            } while (pid == -1);
            if (WIFEXITED(status)) {
                fprintf(stderr, "child %d exited with status %d\n", pid,
                        WEXITSTATUS(status));
                CU_ASSERT_EQUAL(WEXITSTATUS(status), 0);
            } else if (WIFSIGNALED(status)) {
                fprintf(stderr, "child %d exited from signal %d\n", pid,
                        WTERMSIG(status));
                CU_ASSERT(1 == 0);
            } else {
                fprintf(stderr, "child %d exited somehow\n", pid);
                CU_ASSERT(1 == -1);            
            }
            break;
    }
    return 0;
}
