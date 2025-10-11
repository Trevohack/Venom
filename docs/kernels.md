

# The Kernel 

## Venom target

* **Linux 6.x series** — Venom was developed against kernels in the 6.x line. This means internal symbols, syscall entry points, and certain internal APIs align with modern kernel layouts and the helpers introduced in the 6.x tree. When reading compatibility notes, assume the behavior and naming are modern (kallsyms, seq_file implementations, namespaces, and mount propagation behavior as in 6.x).
* Venom was mostly tested on kernel `6.12` 

## Why kernel version matters

* Internal symbol names, offsets, and helper functions change between major versions. Hooks or any low-level kernel work need to account for those changes
* New security features (e.g., more restrictive lockdown modes, retpoline-like mitigations, hardened KASLR variants) and configuration options (CONFIG options) vary by version and affect behavior.\
* Subsystems evolve: networking internals, VFS, seq_file implementations, and module loader paths have been tweaked across major releases.

## Other Linux families to be aware of

* **5.x series** — Still widespread in older distros. Many structures are similar to 6.x but some internal helper names differ. Backports exist, so behavior can be mixed. 
* **4.x / 3.x** — Found on older appliances and embedded gear. Internal layouts and helper availability can be quite different; expect missing features that newer code relies on.
* **Long-term support (LTS) kernels** — Often used in enterprise or appliances (e.g., 4.19, 5.10). LTS kernels can have backported fixes and cherry-picked features; compatibility is not guaranteed by version number alone.


## Practical notes for researchers & defenders

* Always record exact kernel version string (`uname -a`) and `dmesg` output when analyzing a host.
* For testing, use kernels close to the target (same major, vendor patches, and CONFIG set).
* When comparing behavior across systems, prefer behavioral signals (missing sockets, failed module ops) over relying solely on symbol names.
