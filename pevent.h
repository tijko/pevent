#ifndef PEVENT
#define PEVENT

#include <unistd.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>


#define PEVENT_ERROR(msg)   \
    do {                    \
        perror(msg);        \
        exit(1);            \
    } while (1)             \

#define CN_MAX_DATA 1024

struct pevent_nlmsg {
    struct nlmsghdr nl_pevent_hdr;
    struct cn_msg cn;
    char *cn_data[CN_MAX_DATA];
};

#define PEVENT_NLMSG_SIZE(load) NLMSG_LENGTH(sizeof(load)) +      \
                                             sizeof(struct cn_msg)

struct pevent {
    struct msghdr msg;
    struct iovec io;
    struct sockaddr_nl nladdr;
    struct pevent_nlmsg nl_pevent_msg;
    int conn;
};

#define NL_ADDR_SIZE sizeof(struct sockaddr_nl)

void init_connection(struct pevent *ev);

struct pevent *create_pevent(void);

#define FREE_PEVENT(ev)   \
    if (ev != NULL) free(ev);     \

jmp_buf jmp_addr;

void pevent_cleanup(int signal_number);

void pevent_connect(struct pevent *ev);

void pevent_listen(struct pevent *ev);

void parse_pevent(struct proc_event *cn_event);

void print_fork(struct fork_proc_event *fork_event);

void print_exec(struct exec_proc_event *exec_event);

void print_id(struct id_proc_event *id_event, int id);

void print_sid(struct sid_proc_event *sid_event);

void print_ptrace(struct ptrace_proc_event *ptrace_event);

void print_comm(struct comm_proc_event *comm_event);

void print_coredump(struct coredump_proc_event *coredump_event);

void print_exit(struct exit_proc_event *exit_event);

#endif
