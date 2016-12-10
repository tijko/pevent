#include <poll.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "pevent.h"


void pevent_cleanup(int signal_number)
{
    printf("Pevent received SIGINT <%d>\n", signal_number);
    longjmp(jmp_addr, 1);
}

void init_connection(struct pevent *ev)
{   
    ev->conn = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    
    if (ev->conn < 0)
        PEVENT_ERROR("init-connection-socket");

    memset(&(ev->nladdr), 0, NL_ADDR_SIZE);
    ev->nladdr.nl_family = AF_NETLINK;
    ev->nladdr.nl_groups = CN_IDX_PROC;

    if (bind(ev->conn, (struct sockaddr *) &(ev->nladdr), NL_ADDR_SIZE) < 0)
        PEVENT_ERROR("init-connection-bind");

    pevent_connect(ev);

    return;
}

void pevent_connect(struct pevent *ev)
{
    struct nlmsghdr *nlh = &(ev->nl_pevent_msg.nl_pevent_hdr);
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_len = PEVENT_NLMSG_SIZE(enum proc_cn_mcast_op); 
    ev->nl_pevent_msg.cn.id.idx = CN_IDX_PROC;
    ev->nl_pevent_msg.cn.id.val = CN_VAL_PROC;
    ev->nl_pevent_msg.cn.len = sizeof(PROC_CN_MCAST_LISTEN);
    int cn_data = PROC_CN_MCAST_LISTEN;
    memcpy(&(ev->nl_pevent_msg.cn_data), &cn_data,
             sizeof(enum proc_cn_mcast_op));
    ev->io.iov_base = &(ev->nl_pevent_msg);
    ev->io.iov_len = nlh->nlmsg_len; 
    ev->msg.msg_iov = &(ev->io);
    ev->msg.msg_iovlen = 1;
    ev->msg.msg_name = &(ev->nladdr);
    ev->msg.msg_namelen = NL_ADDR_SIZE;

    if (sendmsg(ev->conn, &(ev->msg), 0) < 0)
        PEVENT_ERROR("pevent-connect-sendmsg");

    return;
}

void print_fork(struct fork_proc_event *fork_event)
{
    printf("FORK\n\tppid:\t%d\n\tptgid:\t%d\n\tpid:\t%d\n\ttgid:\t%d\n",
            fork_event->parent_pid, fork_event->parent_tgid, 
            fork_event->child_pid, fork_event->child_tgid);    
}

void print_exec(struct exec_proc_event *exec_event)
{
    printf("EXEC\n\tpid:\t%d\n\ttgid:\t%d\n", 
            exec_event->process_pid,
            exec_event->process_tgid);
}

void print_id(struct id_proc_event *id_event, int id)
{

    printf("ID\n\tpid:\t%d\n\ttgid:\t%d\n",
            id_event->process_pid, id_event->process_tgid);

    switch (id) {

        case (PROC_EVENT_UID):
            printf("\truid:\t%d\n\teuid:\t%d\n",
                    id_event->r.ruid, id_event->e.euid);
            break;

        case (PROC_EVENT_GID):
            printf("\trgid:\t%d\n\tegid:\t%d\n",
                    id_event->r.rgid, id_event->e.egid);
            break;

        default:
            break;
    }
}

void print_sid(struct sid_proc_event *sid_event)
{
    printf("SID\n\tpid:\t%d\n\ttgid:\t%d\n",
            sid_event->process_pid, sid_event->process_tgid);
}

void print_ptrace(struct ptrace_proc_event *ptrace_event)
{
    printf("PTRACE\n\tpid:\t%d\n\ttgid:\t%d\n"
           "\ttracer_pid:\t%d\n\ttracer_tgid:\t%d\n",
            ptrace_event->process_pid, ptrace_event->process_tgid,
            ptrace_event->tracer_pid, ptrace_event->tracer_tgid);
}

void print_comm(struct comm_proc_event *comm_event)
{
    printf("COMM\n\tpid:\t%d\n\ttgid:\t%d\n", comm_event->process_pid,
                                              comm_event->process_tgid);
}

void print_coredump(struct coredump_proc_event *coredump_event)
{
    printf("COREDUMP\n\tpid:\t%d\n\ttgid:\t%d\n",
            coredump_event->process_pid, coredump_event->process_tgid);
}

void print_exit(struct exit_proc_event *exit_event)
{
    printf("EXIT\n\tpid:\t%d\n\ttgid:\t%d\n"
           "\texit_code:\t%d\n\texit_signal:\t%d\n",
            exit_event->process_pid, exit_event->process_tgid,
            exit_event->exit_code, exit_event->exit_signal);
}

void parse_pevent(struct proc_event *cn_event)
{
    switch (cn_event->what) {

        case (PROC_EVENT_NONE):
            break;

        case (PROC_EVENT_FORK):
            print_fork((struct fork_proc_event *) 
                      ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_EXEC):
            print_exec((struct exec_proc_event *) 
                      ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_UID):
        case (PROC_EVENT_GID):
            print_id((struct id_proc_event *)
                    ((char *) &(cn_event->event_data)), cn_event->what);
            break;

        case (PROC_EVENT_SID):
            print_sid((struct sid_proc_event *)
                     ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_PTRACE):
            print_ptrace((struct ptrace_proc_event *)
                        ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_COMM):
            print_comm((struct comm_proc_event *)
                      ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_COREDUMP):
            print_coredump((struct coredump_proc_event *)
                          ((char *) &(cn_event->event_data)));
            break;

        case (PROC_EVENT_EXIT):
            print_exit((struct exit_proc_event *)
                      ((char *) &(cn_event->event_data)));
            break;

        default:
            break;
    }

}

void pevent_listen(struct pevent *ev, long event_id, int events, long timeout)
{
    struct pollfd polls[] = {{ .fd=ev->conn, .events=POLLIN }};
    ev->io.iov_len = PEVENT_NLMSG_SIZE(struct proc_event);

    /* Callback for specific messages */
    
    int event_count = 0;
    int inc = events ? 1 : 0;

    time_t start = time(NULL);

    while (event_count <= events) {

        if (poll(polls, 1, -1) < 0)
            continue;

        if (recvmsg(ev->conn, &(ev->msg), 0) < 0)
           PEVENT_ERROR("pevent-listen-recvmsg");

        struct proc_event *event = (struct proc_event *) 
                                   ((char *) &(ev->nl_pevent_msg.cn.data));

        if (timeout && (time(NULL) - start) > timeout)
            break;

        if (event->event_data.ack.err == 22 ||
           (event_id && event->what != event_id))
            continue;

        event_count += inc;
        parse_pevent(event); 
    }
}

struct pevent *create_pevent(void)
{
    struct pevent *ev = calloc(1, sizeof *ev);

    if (ev == NULL)
        PEVENT_ERROR("create-pevent-calloc");

    init_connection(ev);

    return ev;
}

static long match_id(char *event_name)
{
    const char *events[] = { "fork", "exec", "uid", "gid", "uid", "sid",
                             "ptrace", "comm", "coredump", "exit" };

    long event_ids[] = { PROC_EVENT_FORK, PROC_EVENT_EXEC,
                         PROC_EVENT_UID, PROC_EVENT_GID,
                         PROC_EVENT_SID, PROC_EVENT_PTRACE,
                         PROC_EVENT_COMM, PROC_EVENT_COREDUMP,
                         PROC_EVENT_EXIT };

    int event_number = 10;

    for (int i=0; i < event_number; i++)
        if (!strcmp(event_name, events[i]))
            return event_ids[i];

    return 0;
}

int main(int argc, char *argv[])
{
    int opt;
    long event_id = 0;
    long timeout = 0;
    int events = 0;

    while ((opt = getopt(argc, argv, "e:c:t:")) != -1) {

        switch (opt) {

            case ('e'):
                event_id = match_id(optarg);
                break;

            case ('c'):
                events = atoi(optarg);
                break;

            case ('t'):
                timeout = atol(optarg);
                break;
        }
    }

    struct sigaction sa = { .sa_handler=pevent_cleanup };
    sigaction(SIGINT, &sa, NULL);

    struct pevent *ev = create_pevent();
    
    if (!setjmp(jmp_addr))
        pevent_listen(ev, event_id, events, timeout);

    FREE_PEVENT(ev);

    return 0;
}

