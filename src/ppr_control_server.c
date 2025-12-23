/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_server.c 
Description: the ppr server module is a JSON based RPC control server that listens for incoming TCP connections on a specified port.
It supports a variety of commands for querying statistics, configuring ports, managing egress table entries, and other control plane functions.
The server uses the jansson library for JSON parsing and construction, and is designed to be extensible with a command table that maps command names 
to handler functions. The server runs in its own thread and interacts with the main application state via shared data structures passed in the thread arguments.

ppr_server is the primary control interface for the PPR application, allowing external clients to monitor and manage the datapath behavior at runtime.

*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h> 
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

#include "ppr_app_defines.h"
#include "ppr_control.h"
#include "ppr_stats.h"
#include "ppr_log.h"

//RPC Library Includes
#include "ppr_stats_rpc.h"
#include "ppr_port_rpc.h"
#include "ppr_acl_rpc.h"

/* API function Defs */
//general commands
static int ppr_cmd_help(json_t *reply_root,json_t *args, ppr_thread_args_t *thread_args);
static int ppr_cmd_ping(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);

/* Command table – defines all supported commands */
const ppr_cmd_def_t ppr_cmd_table[] = {
    /* --------------------------------- General commands --------------------------------- */
    {
        .name        = "help",
        .description = "Return help document describing all supported commands",
        .args_schema = "{}",
        .handler     = ppr_cmd_help,
    },
    {
        .name        = "ping",
        .description = "Ping the control server",
        .args_schema = "{}",
        .handler     = ppr_cmd_ping,
    },

    /* --------------------------------- Stastics commands --------------------------------- */
    {
        .name        = "port_stats",
        .description = "Return per-port xstats + rate metrics",
        .args_schema = "{portno: str(port_number)} // -1 for all ports",
        .handler     = ppr_cmd_port_stats,
    },
    {
        .name        = "mem_stats",
        .description = "Return mempool usage stats",
        .args_schema = "{}",
        .handler     = ppr_cmd_mem_stats,
    },
    /* --------------------------------- ACL Table Commands ----------------------------------- */
    {
        .name        = "ppr_cmd_get_acl_db",
        .description = "Dump the current ACL rule database",
        .args_schema = "{}",
        .handler     = ppr_cmd_get_acl_db,
    },
    {
        .name        = "ppr_cmd_add_acl_rule",
        .description = "Add a new ACL rule to the database",
        .args_schema = "{rule_type: str('ipv4'|'ipv6'|'l2'), rule_cfg: obj(rule_configuration)}",
        .handler     = ppr_cmd_add_acl_rule,
    },
    {
        .name        = "ppr_cmd_update_acl_rule",
        .description = "Update an existing ACL rule in the database",
        .args_schema = "{rule_type: str('ipv4'|'ipv6'|'l2'), rule_id: int(rule_id), rule_cfg: obj(rule_configuration)}",
        .handler     = ppr_cmd_update_acl_rule,
    },
    {
        .name        = "ppr_cmd_delete_acl_rule",
        .description = "Delete an existing ACL rule from the database",
        .args_schema = "{rule_type: str('ipv4'|'ipv6'|'l2'), rule_id: int(rule_id)}",
        .handler     = ppr_cmd_delete_acl_rule,
    },
    {
        .name        = "ppr_cmd_check_acl_status",
        .description = "Check the status of the ACL database",
        .args_schema = "{}",
        .handler     = ppr_cmd_check_acl_status,
    },
    {
        .name        = "ppr_cmd_acl_db_commit",
        .description = "Commit any pending changes to the ACL database",
        .args_schema = "{}",
        .handler     = ppr_cmd_acl_db_commit,
    },
    /* --------------------------------- Flowtable Commands ----------------------------------- */
    
};

const size_t ppr_cmd_table_count = sizeof(ppr_cmd_table) /
                                   sizeof(ppr_cmd_table[0]);

/** 
* Lookup a command definition by name
* @param name
*   Command name string
* @return
*   Pointer to command definition struct, or NULL if not found
**/
const ppr_cmd_def_t *ppr_control_find_cmd(const char *name)
{
    if (!name)
        return NULL;

    for (size_t i = 0; i < ppr_cmd_table_count; i++) {
        if (strcmp(name, ppr_cmd_table[i].name) == 0)
            return &ppr_cmd_table[i];
    }
    return NULL;
}

/* -------------------------------- Control Server Command Functions --------------------------------- */
/** 
* Build a JSON document describing all supported commands
* @return
*   Pointer to JSON root object to return to caller (caller must json_decref() it)
**/
json_t *ppr_control_build_help_doc(void)
{
    json_t *root = json_object();
    json_t *cmds = json_array();

    for (size_t i = 0; i < ppr_cmd_table_count; i++) {
        const ppr_cmd_def_t *d = &ppr_cmd_table[i];

        json_t *cmd = json_object();
        json_object_set_new(cmd, "name",
                            json_string(d->name));
        json_object_set_new(cmd, "description",
                            json_string(d->description));
        json_object_set_new(cmd, "args_schema",
                            json_string(d->args_schema));

        json_array_append_new(cmds, cmd);
    }

    json_object_set_new(root, "commands", cmds);
    return root; /* caller json_decref()s */
}

/* --------------------------------- General commands --------------------------------- */

/**
* Simple help command handler - returns json formated dict of all supported commands
* @param reply_root
*   json root object to populate 
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
static int ppr_cmd_help(json_t *reply_root,json_t *args, ppr_thread_args_t *thread_args)
{
    //silence unused param warnings
    (void)args;
    (void)thread_args;


    json_t *doc = ppr_control_build_help_doc();
    /* merge: reply_root becomes the help doc */
    json_object_update(reply_root, doc);
    json_decref(doc);
    return 0;
}

/**
* Simple ping command handler
* @param reply_root
*   json root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
static int ppr_cmd_ping(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    //silence unused param warnings
    (void)args;
    (void)thread_args;

    int rc = 0;
    rc = json_object_set_new(reply_root, "status", json_string("pong"));
    if (rc < 0){
        return -EINVAL;
    }
    return 0;
}

/* ---------------------------------------- Server Thread and Command Processing Functions ------------------- */
/** 
* Handle an incoming command message, parse and dispatch to appropriate handler
* @param msg
*   Command message string
* @param fd
*   Socket file descriptor to send response on
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if command is invalid
**/
static int handle_command(const char *msg, int fd, ppr_thread_args_t *thread_args) {
    
    int rc = 0; 
    /* Parse the command and confirm is a valid json command if not return error*/
    json_error_t error;
    json_t *reply_root = json_loads(msg, 0, &error);
    if (!reply_root) {
        json_t *err = json_pack("{s:s}", "error", "invalid JSON");
        char *reply = json_dumps(err, 0);
        send(fd, reply, strlen(reply), 0);
        free(reply);
        json_decref(err);
        return -EINVAL;
    }
    PPR_LOG(PPR_LOG_CTL, RTE_LOG_DEBUG, "Control server parsed JSON command successfully: %s\n",msg);
    /* Extract command as string, keep args as json for flexible parsing per command*/
    const char *cmd_str   = json_string_value(json_object_get(reply_root, "cmd"));
    json_t *args          = json_object_get(reply_root, "args");
    json_t *reply         = json_object();
    
    /* main logic for selecting how to process a command. lookup command in command table and dispatch to handler */
    if (!cmd_str) {
        json_object_set_new(reply, "error", json_string("missing cmd"));
        rc = -EINVAL;
    } else {
        const ppr_cmd_def_t *def = ppr_control_find_cmd(cmd_str);

        if (!def) {
            json_object_set_new(reply, "error", json_string("unknown command"));
            rc = -EINVAL;
        } else {
            rc = def->handler(reply, args, thread_args);
            if (rc < 0) {
                json_object_set_new(reply, "error", json_string("command failed"));
            }
            else {
                json_object_set_new(reply, "status", json_string("success"));
            }
        }
    }

    char *reply_str = json_dumps(reply, 0);
    PPR_LOG(PPR_LOG_CTL, RTE_LOG_DEBUG, "Control server sending reply: %s\n", reply_str);
    //send with newline terminator
    if (reply_str != NULL) {
        size_t len = strlen(reply_str);
        send(fd, reply_str, len, 0);
        send(fd, "\n", 1, 0);
        free(reply_str);
    }
    json_decref(reply);
    json_decref(reply_root);

    return rc;
}

/** 
* Main control server thread function - listens for incoming TCP connections on specified port,
* processes received commands and returns responses.
* @param arg
*   Pointer to pthread args structure
* @return
*   Always returns 0
**/
void *run_ppr_app_server_thread(void *arg) {
    //reclass arg structs passed from the main thread
    ppr_thread_args_t *thread_args  = (ppr_thread_args_t *)arg;
    unsigned int ctl_port           = thread_args->controller_port;
    uint64_t successful_connections = 0;
    int rc = 0;
    /* Create an IPv4 stream oriented (TCP) socket handle */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* Configure default socket options */
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Build socket address properties, bind to CTRL_PORT and listen to local interface only 
       Assumption is DPDK server only communicates with locally running Pcap Replay python service */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctl_port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    /* Bind server to address struct */    
    if (bind(srv_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        pthread_exit((void *)-1);
    }

    /* Start listening, backlog = 16 = max 16 outstanding TCP connections */
    listen(srv_fd, 16);

    //mark thread ready
    atomic_store_explicit(&thread_args->thread_ready, true, memory_order_relaxed);

    //wait for app ready flag from main thread
    while (atomic_load_explicit(thread_args->app_ready, memory_order_relaxed) == false) {
        rte_pause();
    }

    /* Main processing loop - accept connection and use handle_command function to process*/
    char buf[MAX_SOCK_PAYLOAD];
    char command[MAX_SOCK_PAYLOAD];
    long unsigned int command_len = 0; 

    //main thread loop
    while(!force_quit) {
        int good_command = 1; 
        struct pollfd pfd;
        pfd.fd     = srv_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        // Wait up to 500ms for a new connection (tune as you like)
        int pret = poll(&pfd, 1, 500);
        if (pret < 0) {
            if (errno == EINTR) {
                // Interrupted by signal: re-check force_quit and continue
                continue;
            }
            PPR_LOG(PPR_LOG_CTL, RTE_LOG_ERR,
                    "poll() on srv_fd failed: %s\n", strerror(errno));
            break;
        }

        if (pret == 0) {
            // Timeout: no new connection, just loop back and re-check force_quit
            continue;
        }

        if (!(pfd.revents & POLLIN)) {
            // Some other event (error/hup). Up to you how to handle.
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                PPR_LOG(PPR_LOG_CTL, RTE_LOG_ERR,
                        "poll() error/hup on srv_fd, revents=0x%x\n", pfd.revents);
                break;
            }
            continue;
        }

        // There is at least one pending connection now; accept will not block for long.
        int cli_fd = accept(srv_fd, NULL, NULL);
        if (cli_fd < 0) {
            if (errno == EINTR) {
                // Interrupted by signal; check force_quit and loop again
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Rare race: poll said readable but nothing now; just continue
                continue;
            }
            // If srv_fd was closed from another thread as part of shutdown:
            if (errno == EBADF && force_quit) {
                break;
            }

            PPR_LOG(PPR_LOG_CTL, RTE_LOG_ERR,
                    "accept() failed: %s\n", strerror(errno));
            continue;
        }

        successful_connections++;
        PPR_LOG(PPR_LOG_CTL, RTE_LOG_DEBUG, "[CTRL] Client connected - Connection Count: %ld\n", successful_connections);
        /* process received data */
        while (good_command == 1) {
            
            /* Read data from client */
            ssize_t n = recv(cli_fd, buf, sizeof(buf), 0);
            // if connection fails, break 
            if (n <= 0) {
                break;
            }

            /* iterate through received data */
            for (int i=0; i < n ; i++) { 
                // grab next byte
                char c = buf[i];
                // if we've hit the terminator character
                if (c == '\n') {
                    //terminate command line 
                    command[command_len] = '\0';
                    
                    //if line contains valid data, process
                    if (command_len > 0) {
                        PPR_LOG(PPR_LOG_CTL, RTE_LOG_DEBUG, "Control server received command: %s\n", command);
                        rc = handle_command(command,cli_fd,thread_args);
                        if (rc < 0){
                            PPR_LOG(PPR_LOG_CTL, RTE_LOG_ERR, "Control server failed to process command: %s\n", command);
                        }
                    }

                    command_len = 0; 

                /* else, keep processing received data */
                } else {
                    // if we have room in buffer, keep adding data 
                    if(command_len < sizeof(command) -1){
                        command[command_len++] = c;
                    
                    //overflow case, return malformed command error
                    } else {
                        PPR_LOG(PPR_LOG_CTL, RTE_LOG_ERR, "Control server received malformed command (buffer overflow)\n"); 
                        json_t *err = json_pack("{s:s}", "error", "Malformed Command");
                        char *reply = json_dumps(err, 0);
                        send(cli_fd, reply, strlen(reply), 0);
                        free(reply);
                        json_decref(err);
                        command_len = 0; 
                        good_command = 0; 
                        break;
                    }
                }
            }
            
            //reset buffers 
            memset(buf,0,sizeof(buf));
            memset(command,0,sizeof(command));

        }
        close(cli_fd);
        //printf("[CTRL] Client disconnected\n");
    }
    PPR_LOG(PPR_LOG_CTL, RTE_LOG_INFO, "\n\tControl Server Thread - Thread Exiting\n");
    close(srv_fd);
    return (void*)0;
}
