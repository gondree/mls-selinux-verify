.PHONY: all clean policy install-policy uninstall-policy

VPATH  += policy src
OS = `uname -r`

CC = gcc
MAKE = make
RM = rm
SEMODULE = semodule
PMAKEFILE = /usr/share/selinux/devel/Makefile

INC     += -I../include
CFLAGS  += -g
LDFLAGS += -lcunit -lselinux -lrt

BINS  = mls_test 
BINS += mls_file_helper mls_shm_helper mls_msg_helper mls_sem_helper
BINS += mls_pipe_helper

OBJS  = mls_test.o mls_sem.o mls_msg.o mls_shm.o mls_file.o mls_pipe.o
OBJS += mls_support.o

all: $(BINS) log files

log files:
	mkdir $@

mls_test: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

%_helper: %_helper.o
	$(CC) $^ $(LDFLAGS) -o $@

policy:
	$(MAKE) -C policy -f $(PMAKEFILE)

install-policy: mls_test.pp mls_test_privileges.pp
	$(SEMODULE) -i policy/mls_test.pp
	$(SEMODULE) -i policy/mls_test_privileges.pp

uninstall-policy:
	$(SEMODULE) -r mls_test_privileges
	$(SEMODULE) -r mls_test

clean:
	$(RM) -f *.o $(BINS)
	$(RM) -rf policy/tmp policy/*.if policy/*.pp policy/*.fc

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $^ -o $@

