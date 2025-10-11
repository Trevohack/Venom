
# CONTRIBUTING 

Thank you for your interest in contributing to **Venom**. This document explains how to report issues, propose changes, and submit code in a way that keeps the project healthy, auditable, and safe for everyone.

---


## Purpose & scope

Venom is a research-oriented kernel module to manipulate linux systems

## Code of conduct

We follow a standard open-source code of conduct: be respectful, focus on constructive feedback, do not harass or threaten maintainers or other contributors, and keep discussions professional. Repeated or severe violations may result in being blocked from the project.

---

## Ways to contribute

### 1) Reporting bugs

* Use the issue tracker with a clear title and steps to reproduce. Include environment details (kernel version, distro, compiler, module build flags), logs, and any relevant dmesg output.
* Label the issue: `bug`, `kernel`, `docs`, `security` (if it concerns potential vulnerabilities).

### 2) Feature requests

* Open an issue describing the motivation, high-level design, and potential security/privacy implications.
* If you want to implement it, say so and provide a short plan or draft design.

### 3) Documentation fixes

* Small typos or formatting fixes: submit a PR directly.
* Larger documentation: open an issue for discussion first.

### 4) Code contributions (PRs)

* Fork the repository 
* Keep changes small and focused one logical change/new hooks/modifications per PR 
* Follow the Pull Request checklist below.
* Follow the structure already implemented (all hooks should be under hooks directory, any changes to venom.c should follow the earlier hooking patterns)

```
Venom/
├── hooks/                  
│   ├── read.h
│   ├── write.h              
│   ├── insmod.h             
│   └── ...                  
│
├── ftrace/             
│   └── ftrace.h           
├── include/ 
│   ├── headers.h
│
├── venom.c 
├── Makefile                
└── README.md 
``` 

---

## Development setup

### Prerequisites

* A reproducible test environment (VM or disposable machine). **Never test kernel modules on production systems.**
* Kernel headers matching your running kernel (e.g., `linux-headers-$(uname -r)`).
* Tools: `make`, `gcc`, `clang` (optional), `git`, `dmesg`, `gdb` (userspace), and a reliable serial/VM console for kernel logs.

### Building

1. `make` — builds the module and test utilities.
2. `make test` — runs the automated test suite (where available).
3. Install modules in an isolated VM only: `sudo insmod venom.ko` (or use a signed module workflow).

---

## Coding standards

* Language: C for kernel components, Python/Go/JS/Bash for tooling/docs as applicable.
* Naming: prefer clear, non-ambiguous names.
* Comments: explain *why* (design rationale) not only *what*.
* For logging follow the logging system implemented by Venom (`TLOG_*` instead of `printk`)


| Symbol | Level | Description |
|--------|-------|-------------|
| ✓ | TLOG_INF | Normal operations, successful hooks |
| ⚠ | TLOG_WARN | Suspicious activity detected |
| ✗ | TLOG_ERROR | Hook failures, errors |
| ☠ | TLOG_CRIT | Critical failures, security breaches |

## Thank You! 
