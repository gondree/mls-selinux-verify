/* 
 * A Unit test for Bell-LaPadula enforcement under SELinux-MLS
 *
 * \author Copyright (c) 2013, Mark Gondree
 * \author Copyright (c) 2013, Aaron Flemming
 * \date 2013-2013
 * \copyright BSD 2-Clause License
 *            See http://opensource.org/licenses/BSD-2-Clause
 */
#ifndef __TEST_MLS_SUPPORT_H__
#define __TEST_MLS_SUPPORT_H__

#define LVL_HIGH    "s15"
#define LVL_LOW     "s0"
#define LVL_SYSLOW  "s0"
#define AT_LOW     0
#define AT_HIGH    1

#define log_high "log/high_log.txt"
#define log_low  "log/low_log.txt"

#define LOW_CONTENTS    "abcdef"
#define HIGH_CONTENTS   "ABCDEF"

#define MODE_RWX 0777
#define MODE_R   0444
#define MODE_W   0222

#define TEST_KEY_ID  0xc4
#define MAX_STRING 128
#define MAX_TRIES 3
#define WAIT_TIME 1

struct shared_space_t {
    unsigned int state;     // Ready, Writing, Closed
    unsigned int counter;   // Version of the contents
    char data[MAX_STRING];  // Data to pass
};
#define MEM_SIZE (sizeof(struct shared_space_t))

#define STATE_READY   1
#define STATE_WRITING 2
#define STATE_DONE    3


char *build_new_range(const char *newlevel, const char *range);
void chcon_to_level(const char *level_s);
int create_file(const char *lvl, const char *path, const char *data);
int fork_to_lvl(const char *lvl, char * const argv[]);

#endif

