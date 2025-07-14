<!-- regenerate: off -->

# HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency

This is the working area for the individual Internet-Draft, "HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency".

* [Editor's Copy](https://hiae-aead.github.io/draft-pham-hiae/#go.draft-pham-hiae.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-pham-cfrg-hiae)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-pham-cfrg-hiae)
* [Compare Editor's Copy to Individual Draft](https://hiae-aead.github.io/draft-pham-cfrg-hiae/#go.draft-pham-cfrg-hiae.diff)

## Overview

HiAE is an AES-based AEAD cipher optimized for cross-platform efficiency (ARM and x86), achieving top speeds on the latest ARM and x86 architectures.

![XAXX structure](https://raw.github.com/hiae-aead/draft-pham-hiae/master/media/xaxx.png)

[White Paper on ePrint](https://eprint.iacr.org/2025/377)

## Known Implementations

| Name                                                                                                           | Language   |
| -------------------------------------------------------------------------------------------------------------- | ---------- |
| [This document's simple implementation](https://github.com/hiae-aead/draft-pham-hiae/tree/main/implementation) | Python     |
| [Reference implementation](https://github.com/Concyclics/HiAE/tree/main)                                       | C          |
| [libhiae](https://github.com/jedisc1/libhiae)                                                                  | C          |
| [Zig-HiAE](https://github.com/jedisct1/zig-hiae)                                                               | Zig        |
| [JavaScript (TypeScript)](https://github.com/jedisc1/hiae.js)                                                  | JavaScript |

## Contributing

See the
[guidelines for contributions](https://github.com/hiae-aead/draft-pham-hiae/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

