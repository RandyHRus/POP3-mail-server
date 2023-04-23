#include "netbuffer.h"
#include "mailuser.h"
#include "server.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>

#define MAX_LINE_LENGTH 1024

typedef enum state
{
    Authorization_init,
    Authorization_userDone,
    Transaction,
    Update,
} State;

struct mail_item
{
    char file_name[2 * NAME_MAX];
    size_t file_size;
    int deleted;
};

typedef struct serverstate
{
    int fd;
    net_buffer_t nb;
    char recvbuf[MAX_LINE_LENGTH + 1];
    char *words[MAX_LINE_LENGTH];
    int nwords;
    State state;
    struct utsname my_uname;
    // TODO: Add additional fields as necessary
    char user[MAX_LINE_LENGTH];
    mail_list_t mail_list;
} serverstate;
static void handle_client(int fd);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Invalid arguments. Expected: %s <port>\n", argv[0]);
        return 1;
    }
    run_server(argv[1], handle_client);
    return 0;
}

// syntax_error returns
//   -1 if the server should exit
//    1 otherwise
int syntax_error(serverstate *ss)
{
    if (send_formatted(ss->fd, "-ERR %s\r\n", "Syntax error in parameters or arguments") <= 0)
        return -1;
    return 1;
}

// checkstate returns
//   -1 if the server should exit
//    0 if the server is in the appropriate state
//    1 if the server is not in the appropriate state
int checkstate(serverstate *ss, State s)
{
    if (ss->state != s)
    {
        if (send_formatted(ss->fd, "-ERR %s\r\n", "Bad sequence of commands") <= 0)
            return -1;
        return 1;
    }
    return 0;
}

// All the functions that implement a single command return
//   -1 if the server should exit
//    0 if the command was successful
//    1 if the command was unsuccessful

// arugments: none
// restrictions: none
// responses: +OK
//      The POP3 server removes all messages marked as deleted
//      from the maildrop and replies as to the status of this operation.
int do_quit(serverstate *ss)
{
    dlog("Executing quit\n");

    if (ss->state == Transaction)
    {
        ss->state = Update;
    }

    send_formatted(ss->fd, "+OK POP3 server signing off\r\n");
    mail_list_destroy(ss->mail_list);
    return -1;
}

// arguments:  a string identifying a mailbox (required), which is of
//             significance ONLY to the server (required)
// restrictions: may only be given in the AUTHORIZATION state after the POP3
//               greeting or after an unsuccessful USER or PASS command
// responses:
//      +OK name is a valid mailbox
//      -ERR never heard of mailbox name
int do_user(serverstate *ss)
{
    dlog("Executing user\n");

    if (ss->nwords != 2)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Authorization_init) != 0)
    {
        return 1;
    }

    if (is_valid_user(ss->words[1], NULL) == 0)
    {
        dlog("not in right state\n");
        send_formatted(ss->fd, "-ERR never heard of mailbox name\r\n");
        return 1;
    }

    ss->state = Authorization_userDone;
    strncpy(ss->user, ss->words[1], strlen(ss->words[1]));
    ss->user[strlen(ss->words[1])] = 0;
    ss->mail_list = load_user_mail(ss->user);
    send_formatted(ss->fd, "+OK name is a valid mailbox\r\n");
    return 0;
}

// arguments:  a server/mailbox-specific password (required)
// restrictions: may only be given in the AUTHORIZATION state immediately
//               after a successful USER command
// responses:
//      +OK maildrop locked and ready
//      -ERR invalid password
//      -ERR unable to lock maildrop
int do_pass(serverstate *ss)
{
    dlog("Executing pass\n");

    if (ss->nwords != 2)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        ss->state = Authorization_init;
        return 1;
    }

    if (checkstate(ss, Authorization_userDone) != 0)
    {
        ss->state = Authorization_init;
        return 1;
    }

    if (is_valid_user(ss->user, ss->words[1]) == 0)
    {
        dlog("Invalid password for user: %s\n", ss->user);
        send_formatted(ss->fd, "-ERR invalid password\r\n");
        ss->state = Authorization_init;
        return 1;
    }

    ss->state = Transaction;
    send_formatted(ss->fd, "+OK maildrop locked and ready\r\n");
    return 0;
}

// arguments: none
// restrictions: may only be given in the TRANSACTION state
// Possible Responses:
//    "+OK" followed by a single
//    space, the number of messages in the maildrop, a single
//    space, and the size of the maildrop in octets.
int do_stat(serverstate *ss)
{
    dlog("Executing stat\n");

    if (ss->nwords != 1)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    int num_messages = mail_list_length(ss->mail_list, 0);
    int size = mail_list_size(ss->mail_list);

    send_formatted(ss->fd, "+OK %d %d\r\n", num_messages, size);

    return 0;
}

// arguments: message number (optional)
// restrictions: may only be given in the transaction state
// Possible Responses:
//        +OK scan listing follows
//        -ERR no such message
// if argument given: respond with line containing info for that message
// if no argument given: multiline response. for each message in maildrop, respond with line containing info.
int do_list(serverstate *ss)
{
    dlog("Executing list\n");

    if (ss->nwords != 1 && ss->nwords != 2)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    // no argument case
    if (ss->nwords == 1)
    {
        size_t list_length = mail_list_length(ss->mail_list, 0);
        size_t list_size = mail_list_size(ss->mail_list);

        send_formatted(ss->fd, "+OK %zu messages (%zu octects)\r\n", list_length, list_size);

        size_t list_length_inc_deleted = mail_list_length(ss->mail_list, 1);
        for (int i = 0; i < list_length_inc_deleted; i++)
        {
            mail_item_t mail = mail_list_retrieve(ss->mail_list, i);
            if (mail != NULL)
            {
                size_t mail_size = mail_item_size(mail);
                send_formatted(ss->fd, "%d %zu\r\n", i + 1, mail_size);
            }
        }
        send_formatted(ss->fd, ".\r\n");

        return 0;
    }

    // argument exists case
    if (ss->nwords == 2)
    {
        char *e;
        int msg_number = strtol(ss->words[1], &e, 10);
        if (*e != '\0')
        {
            send_formatted(ss->fd, "-ERR Invalid argument\r\n");
            return 1;
        }

        mail_item_t mail_item = mail_list_retrieve(ss->mail_list, msg_number - 1);

        if (mail_item == NULL)
        {
            send_formatted(ss->fd, "-ERR no such message\r\n");
            return 1;
        }

        size_t mail_size = mail_item_size(mail_item);
        send_formatted(ss->fd, "+OK %d %zu\r\n", msg_number, mail_size);

        return 0;
    }

    return 1;
}

// arguments: a message number (required)
// restrictions: may only be given in transaction state
// possible responses
//    +OK message follows
//    -ERR no such message
int do_retr(serverstate *ss)
{
    dlog("Executing retr\n");

    if (ss->nwords != 2)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    char *e;
    int msg_number = strtol(ss->words[1], &e, 10);
    if (*e != '\0')
    {
        send_formatted(ss->fd, "-ERR Invalid argument\r\n");
        return 1;
    }

    mail_item_t mail_item = mail_list_retrieve(ss->mail_list, msg_number - 1);

    if (mail_item == NULL)
    {
        send_formatted(ss->fd, "-ERR no such message\r\n");
        return 1;
    }

    FILE *f = mail_item_contents(mail_item);

    send_formatted(ss->fd, "+OK Message follows\r\n");

    char mail_line[MAX_LINE_LENGTH];
    while (fgets(mail_line, sizeof(mail_line), f))
    {
        if (sizeof(mail_line) > 0 && mail_line[0] == '.')
        {
            // stuff with .
            send_formatted(ss->fd, ".%s", mail_line);
        }
        else
        {
            send_formatted(ss->fd, "%s", mail_line);
        }
    }

    send_formatted(ss->fd, ".\r\n");

    fclose(f);
    return 0;
}

// arguments: none
// restrictions: may only be given in the TRANSACTION state
// possible responses: +OK
int do_rset(serverstate *ss)
{
    dlog("Executing rset\n");

    if (ss->nwords != 1)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    int num_restored = mail_list_undelete(ss->mail_list);
    send_formatted(ss->fd, "+OK %d messages restored\r\n", num_restored);

    return 0;
}

// arguments: none
// restrictions: may only be given in TRANSACTION state
// Possible Responses: +OK
int do_noop(serverstate *ss)
{
    dlog("Executing noop\n");

    if (ss->nwords != 1)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    send_formatted(ss->fd, "+OK\r\n");
    return 0;
}

// arguments: message number (required) that is not marked as deleted
// restriction: may only be given in a TRANSACTION state
// Possible responses:
//      +OK message deleted
//      -ERR no such message
int do_dele(serverstate *ss)
{
    dlog("Executing dele\n");

    if (ss->nwords != 2)
    {
        dlog("Syntax error\n");
        send_formatted(ss->fd, "-ERR Syntax error in arguments\r\n");
        return 1;
    }

    if (checkstate(ss, Transaction) != 0)
    {
        return 1;
    }

    char *e;
    int msg_number = strtol(ss->words[1], &e, 10);
    if (*e != '\0')
    {
        send_formatted(ss->fd, "-ERR Invalid argument\r\n");
        return 1;
    }

    mail_item_t mail_item = mail_list_retrieve(ss->mail_list, msg_number - 1);

    if (mail_item == NULL)
    {
        send_formatted(ss->fd, "-ERR no such message\r\n");
        return 1;
    }

    if (mail_item->deleted == 1)
    {
        send_formatted(ss->fd, "-ERR message already deleted\r\n");
        return 1;
    }

    mail_item_delete(mail_item);

    send_formatted(ss->fd, "+OK message deleted\r\n");

    return 0;
}

void handle_client(int fd)
{
    size_t len;
    serverstate mstate, *ss = &mstate;
    ss->fd = fd;
    ss->nb = nb_create(fd, MAX_LINE_LENGTH);
    ss->state = Authorization_init;
    uname(&ss->my_uname);
    if (send_formatted(fd, "+OK POP3 Server on %s ready\r\n", ss->my_uname.nodename) <= 0)
        return;

    while ((len = nb_read_line(ss->nb, ss->recvbuf)) >= 0)
    {
        if (ss->recvbuf[len - 1] != '\n')
        {
            // command line is too long, stop immediately
            send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n");
            break;
        }
        if (strlen(ss->recvbuf) < len)
        {
            // received null byte somewhere in the string, stop immediately.
            send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n");
            break;
        }
        // Remove CR, LF and other space characters from end of buffer
        while (isspace(ss->recvbuf[len - 1]))
            ss->recvbuf[--len] = 0;
        dlog("Command is %s\n", ss->recvbuf);
        if (strlen(ss->recvbuf) == 0)
        {
            send_formatted(fd, "-ERR Syntax error, blank command unrecognized\r\n");
            break;
        }
        // Split the command into its component "words"
        ss->nwords = split(ss->recvbuf, ss->words);
        char *command = ss->words[0];
        if (!strcasecmp(command, "QUIT"))
        {
            if (do_quit(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "USER"))
        {
            if (do_user(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "PASS"))
        {
            if (do_pass(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "STAT"))
        {
            if (do_stat(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "LIST"))
        {
            if (do_list(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "RETR"))
        {
            if (do_retr(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "RSET"))
        {
            if (do_rset(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "NOOP"))
        {
            if (do_noop(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "DELE"))
        {
            if (do_dele(ss) == -1)
                break;
        }
        else if (!strcasecmp(command, "TOP") ||
                 !strcasecmp(command, "UIDL") ||
                 !strcasecmp(command, "APOP"))
        {
            dlog("Command not implemented %s\n", ss->words[0]);
            if (send_formatted(fd, "-ERR Command not implemented\r\n") <= 0)
                break;
        }
        else
        {
            // invalid command
            if (send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n") <= 0)
                break;
        }
    }
    nb_destroy(ss->nb);
}
