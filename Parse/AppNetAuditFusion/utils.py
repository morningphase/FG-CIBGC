neo4j_url = 'neo4j://127.0.0.1:7687'
neo4j_passwd = "123456"

reverse_set = {'sys_read', 'sys_pread64', 'sys_readv', 'sys_getitimer', 'sys_getpid', 'sys_accept', 'sys_recvfrom',
               'sys_recvmsg', 'sys_getsockname', 'sys_getpeername', 'sys_getsockopt', 'sys_readlink', 'sys_getdents',
               'sys_getcwd', 'sys_gettimeofday', 'sys_getrlimit', 'sys_accept4', 'sys_getrusage', 'sys_getuid',
               'sys_getgid', 'sys_geteuid', 'sys_getegid', 'sys_getppid', 'sys_getpgrp', 'sys_getgroups',
               'sys_getresuid', 'sys_getresgid', 'sys_getpgid', 'sys_getsid', 'sys_getpriority', 'sys_getxattr',
               'sys_lgetxattr', 'sys_fgetxattr', 'sys_getdents64', 'sys_timer_gettime', 'sys_get_mempolicy',
               'sys_readlinkat'}

rule_set = {
    'apache': {
        1: {
        "process_name": 'apache2',
        "action": 'sys_getsockname',
        "port":80
        }
    }
}


