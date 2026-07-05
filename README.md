# ClearSword

## Overview

A DarkSword Kernel exploit C port

I tried to keep it as close to the original as possible, but had to do a few changes to make it work in earlier iOS versions.
These changes and personal modifications will be denoted by `NOTE` comments.
I've added line comments to basically every line of the entire exploit, denoting what each line is supposed to be doing.

Write-up eta s0n. RIP to this great bug.

## CVE

CVE-2025-43520 "Darksword" - race condition in `cluster_write_contig`/`cluster_read_contig` 
## Building

### Build IPA

```bash
make ipa
```

### Build binary

```bash
make binary
```

## Credits

* Apple for the bug
* [wh1te4ever](https://github.com/wh1te4ever) for so_background_thread trick and offsets
* Whoever leaked the chain