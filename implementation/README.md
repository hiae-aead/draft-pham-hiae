# HiAE Python Implementation

This is a simple Python implementation of the HiAE (High-throughput Authenticated Encryption) algorithm that closely follows the specification in the IETF Internet-Draft.

## Overview

This implementation is designed to be a clear, readable reference that directly corresponds to the algorithm description in [draft-pham-cfrg-hiae](https://datatracker.ietf.org/doc/draft-pham-cfrg-hiae/). It prioritizes clarity and correctness over performance, making it ideal for:

- Understanding the HiAE algorithm
- Validating test vectors
- Prototyping and experimentation
- Educational purposes

## Files

- `hiae.py` - The main implementation following the specification
- `test_hiae.py` - Test suite with test vectors from the draft

## Usage

```python
from hiae import hiae_encrypt, hiae_decrypt

# Encryption
ciphertext = hiae_encrypt(key, nonce, plaintext, associated_data)

# Decryption
plaintext = hiae_decrypt(key, nonce, ciphertext, associated_data)
```
