/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef EVENT_DEFS_H
#define EVENT_DEFS_H

#include <linux/limits.h>

#define VERSION 1
#define CODE_BYTES 0xdeadbeef

#define CONFIG_FILE "../ebpf_telemetry.conf"

#define CMDLINE_MAX_ARGS 128
#define CMDLINE_MAX_LEN 32768 // must be power of 2

#define TOTAL_MAX_ARGS 128
#define ARGSIZE  128
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

#define FILEPATH_NUMDIRS 32

#define TTYSIZE 64
#define COMMSIZE 16

#define NUM_REDIRECTS 8

#define MAX_FDS 65535

#define MAX_EVENT_SIZE (65536 - 8)

#define SYSCALL_MAX 335
#define SYSCALL_ARRAY_SIZE 512
#define COMP_ERROR 0
#define COMP_EQ    1
#define COMP_LT    2
#define COMP_GT    3
#define COMP_AND   4
#define COMP_OR    5

#define ARG_MASK 7
#define ACTIVE_MASK 0x1f
#define ACTIVE_SYSCALL 0x20
#define ACTIVE_NOFAIL  0x40
#define ACTIVE_PARSEV  0x80

#define STATUS_VALUE   0x0001
#define STATUS_RC      0x0002
#define STATUS_CRED    0x0004
#define STATUS_COMM    0x0008
#define STATUS_EXE     0x0010
#define STATUS_PWD     0x0020
#define STATUS_EXEINFO 0x0040
#define STATUS_NOTASK  0x0080
#define STATUS_NOARGS  0x0100


// file operations
typedef struct e_path {
    union {
        struct {
            char  pathname[PATH_MAX];
            char  dfd_path[PATH_MAX];
        };
        struct {
            int   dfd;
            void  *pathname_ptr;
        };
    };
} event_path_s;

// file op: open/at, truncate, rename/at/2, rmdir, creat, link/at, unlink/at, symlink/at, chmod, fchmodat, chown, lchown, fchownat, mknod/at
typedef struct e_fileop {
    event_path_s  path1;
    event_path_s  path2;
} event_fileop_s;

// __NR_execve
typedef struct e_execve {
    event_path_s  exe_path;
    unsigned int  args_count;
    unsigned int  cmdline_size;
    char          cmdline[CMDLINE_MAX_LEN];
} event_execve_s;

// __NR_connect: 
typedef struct e_socket {
    struct sockaddr_in addr;
} event_socket_s;

// Event structure
typedef struct e_rec {
    unsigned long int  code_bytes_start; //Always 0xdeadbeef = 3735928559
    unsigned int       version;
    unsigned long      bootns;
    unsigned int       status;
    unsigned long      syscall_id;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
    unsigned int       pid;
    long int           return_code;
    unsigned int       ppid;
    unsigned int       ses;
    char               tty[TTYSIZE];
    char               comm[COMMSIZE];
    char               exe[PATH_MAX];
    unsigned short     exe_mode;
    unsigned int       exe_ouid;
    unsigned int       exe_ogid;
    char               pwd[PATH_MAX];
    unsigned int       auid;
    unsigned int       uid;
    unsigned int       gid;
    unsigned int       euid;
    unsigned int       suid;
    unsigned int       fsuid;
    unsigned int       egid;
    unsigned int       sgid;
    unsigned int       fsgid;
    union {
        event_fileop_s fileop;
        event_execve_s execve;
        event_socket_s socket;
    };
    unsigned long int  code_bytes_end; //Always 0xdeadbeef = 3735928559
} event_s;

// configuration
typedef struct conf {
    unsigned int       userland_pid;
    unsigned char      active[SYSCALL_ARRAY_SIZE]; // b0-b4 count of filters
                                                   // for this syscall;
                                    // b5 = syscall should generate events;
                                    // b6 = no failures; b7 = parse value ok
    unsigned int       timesec[NUM_REDIRECTS];
    unsigned int       timensec[NUM_REDIRECTS];
    unsigned int       serial[NUM_REDIRECTS];
    unsigned int       arch[NUM_REDIRECTS];
    unsigned int       arg0[NUM_REDIRECTS];
    unsigned int       arg1[NUM_REDIRECTS];
    unsigned int       arg2[NUM_REDIRECTS];
    unsigned int       arg3[NUM_REDIRECTS];
    unsigned int       ppid[NUM_REDIRECTS];
    unsigned int       auid[NUM_REDIRECTS];
    unsigned int       cred[NUM_REDIRECTS];
    unsigned int       cred_uid[NUM_REDIRECTS];
    unsigned int       cred_gid[NUM_REDIRECTS];
    unsigned int       cred_euid[NUM_REDIRECTS];
    unsigned int       cred_suid[NUM_REDIRECTS];
    unsigned int       cred_fsuid[NUM_REDIRECTS];
    unsigned int       cred_egid[NUM_REDIRECTS];
    unsigned int       cred_sgid[NUM_REDIRECTS];
    unsigned int       cred_fsgid[NUM_REDIRECTS];
    unsigned int       ses[NUM_REDIRECTS];
    unsigned int       tty[NUM_REDIRECTS];
    unsigned int       comm[NUM_REDIRECTS];
    unsigned int       exe_path[NUM_REDIRECTS];
    unsigned int       pwd_path[NUM_REDIRECTS];
    unsigned int       path_vfsmount[NUM_REDIRECTS];
    unsigned int       path_dentry[NUM_REDIRECTS];
    unsigned int       dentry_parent[NUM_REDIRECTS];
    unsigned int       dentry_name[NUM_REDIRECTS];
    unsigned int       dentry_inode[NUM_REDIRECTS];
    unsigned int       inode_mode[NUM_REDIRECTS];
    unsigned int       inode_ouid[NUM_REDIRECTS];
    unsigned int       inode_ogid[NUM_REDIRECTS];
    unsigned int       mount_mnt[NUM_REDIRECTS];
    unsigned int       mount_parent[NUM_REDIRECTS];
    unsigned int       mount_mountpoint[NUM_REDIRECTS];
    unsigned int       max_fds[NUM_REDIRECTS];
    unsigned int       fd_table[NUM_REDIRECTS];
    unsigned int       fd_path[NUM_REDIRECTS];
} config_s;

// syscall configuration
// arg specifies which of the 6 syscall arguments to match on
// op represents the comparison operator from:
//     COMP_EQ, COMP_LT, COMP_GT, COMP_AND (bitwise AND), COMP_OR (bitwise OR)
//     - these are all ORed so any matches means event is generated
// is_signed represents whether the operation should be a signed one
// value is the value to compare with
typedef struct sysconf {
    char               arg;
    char               op;
    char               is_signed;
    unsigned long      value;
} sysconf_s;

#endif
