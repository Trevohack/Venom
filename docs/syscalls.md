


### Syscalls / Kernel hooks monitored by Venom

# Syscalls / Kernel hooks monitored by Venom (expanded)


| Hook symbol                                                                             | High-level purpose                                                       | Why Venom hooks it (intended behavior)                                                                                                   | Defender notes / what to look for                                                                                                                |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `__x64_sys_write`                                                                       | Kernel entry for `write(2)` → persistent output to files, pipes, fds     | Intercept writes to protect internal tracing state (e.g., prevent ftrace / logging tampering) or to monitor/modify data leaving the host | Unexpected interception of write can alter logs; look for unusual file descriptor handling, unexpected buffering, or extra memcpy-like behavior. |
| `__x64_sys_read`                                                                        | Kernel entry for `read(2)` → reading from files, pipes, sockets          | Intercept reads to protect ftrace and internal state (detect or sanitise reads that would reveal Venom internals)                        | Modified read return values, timing anomalies, or unusual reads on `/proc` devices.                                                              |
| `__x64_sys_pread64`                                                                     | Positional `read` variant (pread64)                                      | Catch direct positional reads that may probe binary regions or debugfs entries without changing file offset (used by analysis tools)     | Repeated positional reads of kernel symbols or binary sections; mismatches in offsets vs. expected behavior.                                     |
| `__x64_sys_pwrite64`                                                                    | Positional `write` variant (pwrite64)                                    | Intercept writes that won't change file offsets (e.g., targeted log tampering)                                                           | Partial-file writes to logs or binaries without corresponding open/truncate activity.                                                            |
| `__x64_sys_openat`                                                                      | Open a file relative to a directory fd — opens device nodes, /proc, etc. | Observe/enforce policies when sensitive files or device nodes are opened (e.g., kernel symbols, debugfs)                                 | Extra permission/time checks on open; unusual caller stacks opening `/proc` or `/sys`.                                                           |
| `__x64_sys_socket`                                                                      | Create endpoints for network comms (TCP/UDP/RAW)                         | Monitor socket creation to detect outbound channels or covert listeners                                                                  | Sudden raw sockets or unusual families; sockets created by non-network daemons.                                                                  |                                                                        |
| `tcp4_seq_show` / `tcp6_seq_show`                                                       | `/proc/net/tcp*` rendering                                               | Hide network socket listings (IPs/ports)                                                                                                 | Cross-check `ss`/pcap vs. `/proc/net` contents.                                                                                                  |
| `udp4_seq_show` / `udp6_seq_show`                                                       | `/proc/net/udp*` rendering                                               | Hide UDP listings                                                                                                                        | Same as TCP cross-checks.                                                                                                                        |
| `tpacket_rcv`                                                                           | AF_PACKET/TPACKET receive path (raw packet capture)                      | Intercept packet receive to filter forensic captures                                                                                     | Compare multiple capture points (host vs. bridge).                                                                                               |
| `__x64_sys_getdents64`                                                                  | Directory enumeration for `readdir` / `ls`                               | Hide files/dirs and detect other hide attempts                                                                                           | Filtered listings, inode-count mismatches, programs repeatedly scanning directories.                                                             |
| `__x64_sys_getdents`                                                                    | 32-bit directory enumeration compatibility                               | Same as getdents64 — catch 32-bit tools / compat layers                                                                                  | Include 32-bit compatibility in audits.                                                                                                          |
| `__x64_sys_mount`                                                                       | Mount filesystems / bind mounts                                          | Observe/filter mounts to affect visibility and propagation                                                                               | Missing/inconsistent entries in `/proc/mounts`, transient mounts.                                                                                |
| `__x64_sys_move_mount`                                                                  | Move mounts / namespaced mounts                                          | Detect moves used to hide files via mount namespaces                                                                                     | Mounts that appear/disappear quickly; differences across namespaces.                                                                             |
| `__x64_sys_unlinkat`                                                                    | Remove a file/dir entry                                                  | Detect or block deletions of audit artifacts or evidence                                                                                 | Sudden unlink attempts on logs; unlink by unexpected processes.                                                                                  |
| `__x64_sys_renameat`                                                                    | Rename/move filesystem entries                                           | Track renames used to obfuscate evidence                                                                                                 | Renames around timestamps of suspicious activity.                                                                                                |
| `__x64_sys_truncate` / `__x64_sys_ftruncate`                                            | Shrink/clear files                                                       | Detect zeroing-out of logs or dumps                                                                                                      | Unexpected file size drops without matching legitimate activity.                                                                 |
| `__x64_sys_statx`                                                                       | File metadata/stat retrieval                                             | Detect probes for file metadata that could reveal hidden artifacts                                                                       | Repeated/stat access on kernel-related or hidden files; altered stat results.                                                                    |
| `__x64_sys_prctl`                                                                       | Process controls (set name, dumpable, seccomp, etc.)                     | Hook to detect attempts to change process properties that hide behavior (e.g., setting dumpable=0 or changing name)                      | Unexpected `prctl` calls setting non-default flags (e.g., `PR_SET_DUMPABLE`, `PR_SET_NAME`).                                                     |
| `__x64_sys_ptrace`                                                                      | Debugging / process memory inspection                                    | Monitor debugger/forensic probes or block ptrace against Venom components                                                                | `ptrace` attempts from unexpected UIDs or from non-parent PIDs.                                                                                  |
| `__x64_sys_process_vm_readv` / `__x64_sys_process_vm_writev`                            | Cross-process memory read/write                                          | Detect direct cross-process memory access (used by debuggers/forensics or offensive tools)                                               | Suspicious read/writev between unrelated processes, especially to protected processes.                                                           |
| `__x64_sys_ioctl`                                                                       | Device/driver-specific control operations                                | Block or intercept ioctls used by anti-rootkit drivers or forensic probes                                                                | Abnormal/blocked ioctl calls against tracing devices or `/dev/*` used by security tools.                                                         |                                                                                       |
| `__x64_sys_kexec_load`                                                                  | Load a new kernel (kexec)                                                | Alert on attempts to change runtime kernel image                                                                                         | Unscheduled kexec attempts or kexec from non-admin contexts.                                                                                     |
| `__x64_sys_init_module` / `__x64_sys_finit_module`                                      | Load a kernel module                                                     | Block/detect insertion of competing kits or defensive drivers                                                                            | Failed module loads, missing `lsmod` entries, suspicious module paths.                                                                           |
| `__x64_sys_delete_module`                                                               | Unload a kernel module                                                   | Prevent removal of Venom or detect module-removal attempts                                                                               | Failed unloads, module entries that refuse to disappear.                                                                                         |
| `__x64_sys_kill`                                                                        | Send signals to processes                                                | Intercept signals aimed at terminating Venom components                                                                                  | Repeated kill attempts or strange signal sequences against protected PIDs.                                                                       ||

* Some audit subsystem calls are less straightforward to hook directly depending on kernel version — list included for defender completeness.

---


### Secure Logging System

Venom implements a **stealth logging mechanism** that operates completely independently from kernel's `dmesg`/`printk`. This prevents attackers from discovering operational details through standard kernel log inspection.

### How it works

Instead of using `printk()` which writes to the kernel ring buffer (visible via `dmesg`), Venom uses a custom logging system that:

- Writes to a hidden file location: `/var/tmp/.X11-cache` (disguised as a system cache file)
- Uses mutex-protected writes to prevent race conditions
- Provides severity levels with visual indicators (✓ ✗ ⚠ ☠)
- Completely bypasses kernel logging infrastructure

### Log Levels

| Symbol | Level | Description |
|--------|-------|-------------|
| ✓ | INFO | Normal operations, successful hooks |
| ⚠ | WARN | Suspicious activity detected |
| ✗ | ERROR | Hook failures, errors |
| ☠ | CRIT | Critical failures, security breaches |

### Viewing Logs

**Plain text:**
```bash
sudo cat /var/tmp/.X11-cache
```

- The file `/var/tmp/.X11-cache` is also hidden from the `getdents` hook 

---

#### Quick guidance for readers (defensive)
- This table documents *which kernel touchpoints* Venom monitors and *why*.  
- If you are a defender: audit for the indicators in the rightmost column (e.g., mismatched `/proc` output, failed module loads, anomalies in read/write behavior, and differences between passive packet captures and `/proc/net`).  
- If you are a researcher: use isolated, instrumented environments (air-gapped VMs, offline snapshots) and follow responsible disclosure and legal guidelines before experimenting.


--- 

> If you stare at the kernel long enough… it starts staring back

