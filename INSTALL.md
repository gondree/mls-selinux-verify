# Supported Builds
The test suite has been used with the following:

* Fedora 13 (2.6.33.3-85.fc13.x86_64)


---
## Using on Fedora 13
### Configure SELinux with the MLS policy

- Assuming a fresh install, with default software options.

- After installation is complete, it goes through the prompts of the initial boot. Create a user with the username of `temporary`.

- After the first boot is complete, log in as the `temporary` user.

- From a terminal window, change to root using the command `su` and edit `/boot/grub.conf` such that:

        timeout=5        
        ...
        #hiddenmenu

- Install MLS packages, tools and dependencies. These are not all necessary, but are convenient for development.

        $ yum install selinux-policy-mls
        $ yum install "Development Tools"        
	    $ yum install libselinux-devel
	    $ yum install man-pages setools checkpolicy audit
	    $ yum install system-config-services
	    $ yum install CUnit CUnit-devel

- Change the SELinux configuration by editing `/etc/selinux/config` so that:

        SELINUX=enforcing
        ...
        SELINUXTYPE=mls

- Tell the file system to relabel itself:

        $ touch /.autorelabel

- Restart in permissive/single user mode: Use the command `reboot`; **directly after this command, the grub boot menu will appear: interrupt it by pressing 'a'** and then add the argument `single enforcing=0` to the end of the boot command, and press return. When the root prompt appears, enter runlevel 3 using the command `init 3`.

 - At the prompt, login as root. Then, change your role:
 
        $ newrole -r secadm_r

 - Reconfigure the allowable login range and delete the temporary user:

        $ semanage user -m -r s0-s15:c0.c1023 user_u
        $ userdel -r temporary


### Install the policy for the test runner

 - Clone/checkout/copy/untar/etc the project files and navigate to the directory.
 
 - Build and install the policy files, introducing the domain `mls_test_u`
 
        $ make policy
        $ make install-policy

### Install the user that drives the tests

 - Configure the default context for `mls_test_u`, by editing `/etc/selinux/mls/contexts/default_contexts` and alter the appropriate line to the following (*order is important*):
 
        system_r:local_login_t:s0   mls_test_r:mls_test_t:s0-s15:c0.c1023 user_r:user_t:s0

 - Configure the default type associated with the `mls_test_r` role, by editing `/etc/selinux/mls/contexts/default_type` and add the following line
 
        mls_test_r:mls_test_t

 - Copy the `user_u` info into `mls_test_u` by doing the following:
 
        $ cp /etc/selinux/mls/contexts/users/user_u /etc/selinux/mls/contexts/users/mls_test_u

 - Make `mls_test_t` a permissive domain:
 
        $ semanage permissive -a mls_test_t

 - Create a test user:

        $ useradd -d /home/testuser -m -Z mls_test_u testuser
        $ semanage login -m -s user_u -r s0-s15:c0.c1023 testuser
        $ chcon -l s0-s15:c0.c1023 /home/testuser
        $ passwd testuser

- Tell the file system to relabel itself, then reboot

        $ touch /.autorelabel
        $ reboot

### Build and run the test suite

Login as the test user and check that the context is correct to begin the tests:

    $ id -Z
    mls_test_u:mls_test_r:mls_test_t:s0-s15:c0.c1023
    
If this is not correct, change your context to make the above correct:

    $ newrole -r mls_test_r

Build and run the tests:

    $ make all
    $ ./mls_test 2> /dev/null
