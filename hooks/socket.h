#ifndef SOCKET_H
#define SOCKET_H

#include "../include/headers.h"

static asmlinkage long (*orig_socket)(const struct pt_regs *regs);

notrace static asmlinkage long hooked_socket(const struct pt_regs *regs) {
    int family = (int)regs->di;
    int type = (int)regs->si;
    
    if (type == SOCK_RAW) {
        TLOG_WARN("[VENOM] Socket created by PID %d UID %d",  current->pid, current_uid().val);
    }
    
    return orig_socket(regs);
} 

#endif 

