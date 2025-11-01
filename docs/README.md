
<div align="center"> 
  <img src="https://i.postimg.cc/wjxL10sc/venom-docs.png" alt="banner" style="max-width:100%; border-radius:12px;"/> 
</div>

<h1 align="center">Venom Docs</h1>

<div align="center">
  <strong>Docs • Guide • Install</strong><br>
  <b><i>A Linux Kernel Module</i></b> 
</div>


## What is Venom?

Venom is a kernel-level rootkit that operates at ring 0 basically the deepest level of your Linux system. It hooks into syscalls (system calls) to monitor, hide, and protect things. Think of it like having a secret agent living in your kernel that can see everything and hide whatever you want.

Current version: `V4.5`  

> [!Important]
> This is for educational purposes. Don't be evil with it. 

--- 


## The Cool Features

### Stealth Mode

Right out of the gate, Venom hides itself from `lsmod`. Once loaded, you won't see it in the module list. It's like being invisible the module is there, it's running, but good luck finding it with standard tools.

### Custom Logging (No More dmesg!)

Here's where things get interesting. Normal rootkits log to `dmesg` which is stupid because anyone can read that. Venom has a completely custom logging system that writes to a hidden file instead.

**How it works:**
- Logs go to `/var/tmp/.X11-cache` (looks like a legit system cache file)
- Uses mutex locks to prevent race conditions
- No kernel ring buffer involvement whatsoever
- Completely silent to `dmesg`, `journalctl`, and audit logs

**Reading the logs:**
```bash
sudo cat /var/tmp/.X11-cache
``` 

The viewer shows:
- ✓ Green for INFO (normal operations)
- ⚠ Yellow for WARNINGS (suspicious activity)
- ✗ Red for ERRORS (something blocked)
- ☠ Red background for CRITICAL 

<img width="1255" height="733" alt="Screenshot 2025-10-12 142905" src="https://github.com/user-attachments/assets/1ee4b289-8a73-457a-95d6-d4cfd0fef886" />

---

## The Hooks (Where the Magic Happens)

Alright, let's talk about what Venom actually hooks. 

### Ftrace Protection (`read` / `write` / `pread64` / `pwrite64`)

**What it does:** Protects the kernel's ftrace (function trace) system from being messed with.

**Why it matters:** Attackers love disabling ftrace because it lets them see what hooks are running. By hooking read/write syscalls, Venom:
- Blocks writes to `/proc/sys/kernel/ftrace_enabled` and `/sys/kernel/tracing/tracing_on`
- Spoofs reads to make ftrace look "off" even when it's on
- Sanitizes `/proc/kallsyms` to hide rootkit symbols

**Example:**
```bash
# Attacker tries this
echo 0 > /proc/sys/kernel/ftrace_enabled

# Venom blocks it silently and logs:
⚠ [WARN] Blocked write to ftrace_enabled: 0 by echo
```

<img width="1205" height="556" alt="Screenshot 2025-10-12 145125" src="https://github.com/user-attachments/assets/0ebdb055-cc28-47e3-8ad4-25764c91665a" />


### Mount Protection

**What it does:** Denies mounting of files


<img width="838" height="338" alt="Screenshot 2025-10-12 145304" src="https://github.com/user-attachments/assets/790ed2a1-cc20-4419-8790-8ada99a67c6c" />


### Directory & File Hiding (`getdents64` / `getdents`)

**What it does:** Hides files and directories from being listed.

**The trick:** When programs like `ls` want to list a directory, they call `getdents64`. Venom intercepts this, filters out entries matching certain patterns, and returns a modified list.

**Hidden patterns:**
- Anything starting with: `trevohack`, `.secret`, `source`, `.X11-cache` 
- The module itself: `venom.ko`

**Cool part:** The files still exist and you can access them if you know the name. You just can't *see* them in listings.

```bash
ls /tmp/                    # Won't show source-code-project
cd /tmp/source-code-project # Still works!
```

<img width="963" height="672" alt="Screenshot 2025-10-12 144346" src="https://github.com/user-attachments/assets/2a1687d9-03b2-4a11-8a29-9bb75107abee" />


### Process Hiding 

**What it does:** Hides specific processes from `/proc` enumeration.

When you run `ps`, it reads `/proc/[PID]/` directories. Venom filters these out based on:
- PIDs you manually add to the hidden list
- Processes with names like: `python3`, `crontab`, `node`, `ssh`
- This list can be extended and modified under the `hooks/pid_hiding.h` file 

**Example scenario:**
```bash
python3 -m http.server 8443 &
# PID: 1337

ps aux | grep python    # Shows nothing
ls /proc/ | grep 1337   # Shows nothing

# But it's still running and serving files
curl localhost:8443     # Works fine
```

### Module Protection (`init_module` / `finit_module` / `delete_module`)

**What it does:** Prevents other kernel modules from being loaded or Venom from being unloaded.

This is basically saying: I'm the only rootkit allowed here. It blocks:
- `insmod` - Can't load new modules
- `modprobe` - Same deal 
- `rmmod venom` - Can't remove Venom 

```bash
sudo insmod attacker.ko
# Blocked!

⚠ [WARN] Blocked unauthorized module load attempt (finit_module) from PID 1234
```

### Privilege Escalation Backdoor (`kill`)

**What it does:** Provides a magic signal to instantly gain root.

Here's the fun part - normally `kill` is used to send signals to processes. But Venom hijacks it:

```bash
kill -64 0    # Magic signal
id            # uid=0(root) - you're now root!
```

**How it works:**
1. Hooks the `kill` syscall
2. Checks if signal is 64 (our magic number) and PID is 0
3. Calls `prepare_creds()` and sets all UIDs to 0
4. Commits the new credentials

<img width="1265" height="178" alt="Screenshot 2025-10-12 144728" src="https://github.com/user-attachments/assets/5f33250e-5a77-473c-9f52-d2eb146d3719" />


### Network Hiding (`tcp4_seq_show` / `udp4_seq_show` / `tpacket_rcv`)

**What it does:** Hides network connections from enumeration tools.

This hooks the functions that display `/proc/net/tcp` and `/proc/net/udp`. When you run `netstat` or `ss`, Venom:
- Filters out connections on port 8443 (or whatever you configure)
- Drops packets in `tcpdump` / `wireshark` for hidden ports
- Makes your C2 server invisible

**Example:**
```bash
python3 server.py --port 8443

netstat -tulpn | grep 8443    # Shows nothing
ss -tulpn | grep 8443          # Shows nothing
tcpdump -i any port 8443      # Captures nothing

curl localhost:8443           # Works perfectly
```

<img width="1258" height="458" alt="Screenshot 2025-10-12 144636" src="https://github.com/user-attachments/assets/50170741-fd60-43bc-a351-20cdac39fbd6" />


### File Protection (`openat` / `unlinkat` / `renameat` / `truncate`) 

**What it does:** Protects critical files from being accessed, deleted, or modified.

**openat:** Monitors and blocks file access
- Detects rapid file enumeration (forensics tools scanning)
- Blocks writes to sensitive files like `/proc/kallsyms`
- Logs access to critical system files

**unlinkat:** Prevents file deletion
- Protects log files (`.X11-cache`)
- Detects mass deletion patterns (evidence destruction)

**renameat:** Blocks file moving/renaming
- Prevents hiding or replacing protected files

```bash
# Attacker tries to clean up
rm /var/tmp/.X11-cache
# Blocked!

⚠ [WARN] BLOCKED deletion attempt: /var/tmp/.X11-cache | PID:1234 (rm) UID:1000
```

<img width="946" height="223" alt="Screenshot 2025-10-12 145445" src="https://github.com/user-attachments/assets/2d92e0c4-b6cd-4c96-9023-fa99205ac261" />


### IOCTL Protection (`ioctl`)

**What it does:** Blocks device control operations that could expose the rootkit.

Forensic tools use `ioctl` to probe devices and gather system info. Venom blocks:
- Network interface enumeration (`SIOCGIFCONF`)
- Terminal manipulation on protected TTYs
- Ptrace-related ioctls


### Log Commands (`execve`) 

**What it does:** Logs enumeration, defensive commands running on the system actively, hence, protecting the system. 

- Blocks forensics tools such as `chkrootkit, rkhunter, lynis, tiger, unhide, volatality`
- Logs commands that use `python, node, java, php, curl, tcpdump` and so on



## Installation & Persistence 

The installer (`implant.sh`) is pretty aggressive about staying persistent:

**5 different methods:**
1. **Systemd service** - Loads on boot
2. **rc.local hook** - Backup for older systems
3. **Cron job** - Checks every 30 minutes, auto-reloads
4. **modules-load.d** - Native kernel loading
5. **initramfs hook** - Early boot, survives kernel updates

Even if an attacker finds and removes one method, the others will bring it back.

**Anti-forensics during install:**
- Clears all logs (auth.log, syslog, journal)
- Disables audit system
- Timestomps files to look 2 years old
- Shreds source code after compilation
- Uses disguised names (`.systemd-journal-cache.ko`)

---




*Built for educational purposes. Use responsibly.*
