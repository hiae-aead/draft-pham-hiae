---
title: "The Fast Software Authenticated Encryption HiAE"
abbrev: "HiAE"
docname: draft-pham-hiae-latest
category: std

ipr: trust200902
keyword: Internet-Draft
# workgroup: Crypto Forum
submissionType: IETF

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: F. Denis
    name: Frank Denis
    organization: Fastly Inc.
    email: fd@00f.net
 -
    ins: P. Pham
    name: Phuong Pham
    organization: Huawei
    email: pham.phuong@huawei.com
 -
    ins: L. Prabel
    name: Lucas Prabel
    organization: Huawei
    email: lucas.prabel@huawei.com
 -
    ins: S. Sun
    name: Sun Shuzhou
    organization: Huawei
    email: sunshuzhou@huawei.com

normative:

  FIPS-AES:
    title: "Advanced encryption standard (AES)"
    rc: "Federal Information Processing Standards Publication 197"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    author:
      -
        org: National Institute of Standards and Technology (NIST)
    date: 2001-11

informative:

  AEGIS:
    title: "AEGIS: A Fast Authenticated Encryption Algorithm (v1.1)"
    venue: CAESAR Competition
    target: https://competitions.cr.yp.to/round3/aegisv11.pdf
    author:
      -
        ins: H. Wu
        name: Hongjun Wu
        org: Nanyang Technological University
      -
        ins: B. Preneel
        name: Bart Preneel
        org: KU Leuven
    date: 2016
  ROCCA-S:
    title: "An Ultra-High Throughput AES-Based Authenticated Encryption Scheme for 6G: Design and Implementation"
    rc: "Cryptology and Network Security (CANS 2023)"
    seriesinfo:
      DOI: 10.1007/978-3-031-50594-2_12
    author:
      -
        ins: R. Anand
        name: Ravi Anand
      -
        ins: S. Banik
        name: Subhadeep Banik
      -
        ins: A. Caforio
        name: Andrea Caforio
      -
        ins: K. Fukushima
        name: Kazuhide Fukushima
      -
        ins: T. Isobe
        name: Takanori Isobe
      -
        ins: S. Kiyomoto
        name: Shisaku Kiyomoto
      -
        ins: F. Liu
        name: Fukang Liu
      -
        ins: Y. Nakano
        name: Yuto Nakano
      -
        ins: K. Sakamoto
        name: Kosei Sakamoto
      -
        ins: N. Takeuchi
        name: Nobuyuki Takeuchi
    date: 2024
  SNOW-V:
    title: "SNOW-V: an AES-based Stream Cipher for 5G and 6G Communication Systems"
    rc: "IACR Transactions on Symmetric Cryptology, 2019(3)"
    seriesinfo:
      DOI: 10.13154/tosc.v2019.i3.1-42
    author:
      -
        ins: P. Ekdahl
        name: Patrik Ekdahl
        org: Ericsson Research
      -
        ins: T. Johansson
        name: Thomas Johansson
        org: Lund University
      -
        ins: A. Maximov
        name: Alexander Maximov
        org: Ericsson Research
      -
        ins: J. Yang
        name: Jing Yang
        org: Ericsson Research
    date: 2019
  AES-NI:
    title: "Intel Advanced Encryption Standard (AES) New Instructions Set"
    target: https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
    author:
      -
        ins: S. Gueron
        name: Shay Gueron
        org: Intel Corporation
    date: 2010
  HiAE:
    title: "HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency"
    rc: "Cryptology ePrint Archive, Paper 2025/377"
    target: https://eprint.iacr.org/2025/377
    author:
      -
        ins: H. Chen
        name: Han Chen
        org: Huawei International Pte., Ltd.
      -
        ins: T. Huang
        name: Tao Huang
        org: Huawei International Pte., Ltd.
      -
        ins: P. Pham
        name: Phuong Pham
        org: Huawei International Pte., Ltd.
      -
        ins: S. Wu
        name: Shuang Wu
        org: Huawei International Pte., Ltd.
    date: 2025
  NIST-LWC:
    title: "NIST Lightweight Cryptography (LWC)"
    target: https://csrc.nist.gov/projects/lightweight-cryptography
    author:
      -
        org: National Institute of Standards and Technology (NIST)
    date: 2025

--- abstract

This document describes the high throughput authenticated encryption algorithm HiAE designed for new wireless generation 6G and data transmission applications.

--- middle

# Introduction

Many recent cryptographic designs have utilized SIMD instructions to achieve high performance, particularly on x86 platforms using AES-NI {{AES-NI}}. AES-NI has become the foundation for many recent high-speed (authenticated) encryption algorithms like AEGIS {{AEGIS}}, SNOW-V {{SNOW-V}}, and Rocca-S {{ROCCA-S}}, which are tailored to take advantage of the parallelism and efficiency offered by these instructions. However, these designs often neglect the architectural differences between x86 and ARM, where SIMD instructions are implemented via NEON rather than AES-NI. This oversight results in inconsistent performance when deploying these algorithms on ARM-based devices, which dominate mobile and embedded systems. The transition to 6G, with its demand for ultra-high data rates and reliance on software-defined
networks (SDN) or  Cloud Radio Access Networks (Cloud RAN), further emphasizes the need for cryptographic algorithms optimized for diverse platforms. While some existing designs achieve remarkable performance on x86—reaching or exceeding 100 Gbps—these same algorithms often perform suboptimally on ARM platforms due to differences in SIMD instruction sets and hardware support for AES round functions. This gap highlights the pressing need for a unified approach that ensures high and consistent performance across both architectures.

Addressing this challenge requires rethinking cryptographic design to leverage the unique capabilities of each platform while maintaining compatibility and efficiency. This motivates our work in developing a cross-platform cryptographic HiAE that achieves competitive performance on both x86 and ARM architectures, meeting the stringent demands of 6G systems.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notations

- `AESL(x)`: `AESL(x) = MixColumns o SubBytes o ShiftRows(x)`, of AES operations {{FIPS-AES}}.
- `a ^ b`: The bitwise exclusive OR operation between a and b.
- `S`: The internal state, composed of 16 blocks, i.e. `S = (S[0], S[1], ..., S[15])`, where `S[i] (0 <= i <= 15)` are blocks and `S[0]` is the first block. The `i`-th state block at round `r` is defined as `S^r[i]`.
- `N`: A `128`-bit nonce.
- `AD_i`: A `128`-bit associated data block.
- `M_i`: A `128`-bit message block.
- `C_i`: A `128`-bit ciphertext block.
- `const_0`: A `128`-bit constant, represented in hexadecimal as `0x3243f6a8885a308d313198a2e0370734`.
- `const_1`: A `128`-bit constant, represented in hexadecimal as `0x4a4093822299f31d0082efa98ec4e6c8`.
- `X || 0^*`: A `128`-bit block string of the concatenation of `X` and the complement of zeros.
-`|M|`: the length in bit of the string `M`.
- `Truncate(x, l)`: Output the upper bits of `x` with length `l`.

## The Round Function

The input of the round function `UpdateFunction(S,X)` of HiAE consists of the state `S` and a data block `X`.
If denoting the output by `Snew`, `Snew:=UpdateFunction(S,X)` can be defined as follows:

~~~
Snew[15] = AESL(S[0] ^ S[1]) ^ AESL(S[13]) ^ X,
Snew[14] = S[15],
Snew[13] = S[14],
Snew[12] = S[13] ^ X,
Snew[11] = S[12],
Snew[10] = S[11],
Snew[9] = S[10],
Snew[8] = S[9],
Snew[7] = S[8],
Snew[6] = S[7],
Snew[5] = S[6],
Snew[4] = S[5],
Snew[3] = S[4],
Snew[2] = S[3] ^ X,
Snew[1] = S[2],
Snew[0] = S[1]
~~~

# Algorithm Description

In this section, we describe the specification of our design.

## Specification

HiAE is structured into four phases: initialization, processing of associated data, encryption, and finalization. HiAE has a 2048-bit state, made of sixteen 128-bit blocks `S_0||S_1||...||S_{15}`. The parameters for this algorithm, that are consistent with the definition in {{!RFC5116, Section 4}}, are defined as:

- `K_LEN` (key length): 32 bytes (256 bits).
- `P_MAX` (maximum length of the plaintext): `2^61 - 1` bytes (`2^64 - 8` bits).
- `A_MAX` (maximum length of the associated data): `2^61 - 1` bytes (`2^64 - 8` bits).
- `N_MIN` (minimum nonce length) = `N_MAX` (maximum nonce length) = `16` bytes (`128` bits).
- `C_MAX` (maximum ciphertext length) = `P_MAX + tag length = (2^61 - 1) + 16 bytes` (`2^64 - 8 + 128` bits).

In more details, HiAE takes as input a `256`-bit key `K = K_0||K_1`, a `128`-bit nonce `N`, the associated data `AD`, and the message `M`.
The output includes the ciphertext `C` where `|C| = |M|` and a `128`-bit tag `T`. Initially, `AD` and `M` are padded with `0` to ensure their lengths are multiples of `128` as  `Pad(AD) = AD||0* = AD_0|| ... || AD_{|AD|/128-1}` and `Pad(M) = M||0* = M_0|| ... || M_{|M|/128-1}`.
The encryption and authentication process are described below.

### Initialization

First, the state is loaded with `(N, K_0, K_1)` as follow:

~~~
  S[0] = const_0,
  S[1] = K_1,
  S[2] = N,
  S[3] = const_0,
  S[4] = ZERO(128),
  S[5] = N ^ K_0,
  S[6] = ZERO(128),
  S[7] = const_1,
  S[8] = N ^ K_1,
  S[9] = ZERO(128),
  S[10] = K_1,
  S[11] = const_0,
  S[12] = const_1,
  S[13] = K_1,
  S[14] = ZERO(128),
  S[15] = const_0 ^ const_1.
~~~

Next, the state is updated with `32 UpdateFunction(S, const_0)`, then XORed with the key one more:

~~~
  S[9] = S[9] ^ K_0,
  S[13] = S[13] ^ K_1.
~~~

### Processing the Associated Data

Following initialization, the associated data `AD` is used to update the state as:

~~~
   for i = 0 to |AD|/128 - 1:
      S = UpdateFunction(S, AD_i)
   end for
~~~

This phase is skipped if the associated data is empty.

### Encryption

At each step of the encryption, a `128`-bit message block is used to update the state, and `M_i` is then encrypted to produce `C_i` following, and skipped the phase if the message is empty.

~~~
   for i = 0 to |M|/128 - 1:
      C_i = AESL(S[0] ^ S[1]) ^ S[9] ^ M_i
      S = UpdateFunction(S, M_i)
   end for
~~~

### Finalization

After encrypting all the message blocks, the state is updated again with the lengths of associated data and message as:

~~~
   for i = 0 to 31:
      S = UpdateFunction(S, |AD||||M|)
   end for
~~~

then the authentication tag is generated as:

~~~
   T = S[0] ^ S[1] ^ ... ^ S[15].
~~~

## HiAE Algorithm

A pseudo algorithm of HiAE is described in the following.

~~~
HiAE Algorithm. The internal structures of HiAE are:

   procedure Initialization(N, K_0, K_1)
      S[0] = const_0,
      S[1] = K_1,
      S[2] = N,
      S[3] = const_0,
      S[4] = ZERO(128),
      S[5] = N ^ K_0,
      S[6] = ZERO(128),
      S[7] = const_1,
      S[8] = N ^ K_1,
      S[9] = ZERO(128),
      S[10] = K_1,
      S[11] = const_0,
      S[12] = const_1,
      S[13] = K_1,
      S[14] = ZERO(128),
      S[15] = const_0 ^ const_1.
      for i = 0 to 31 do
         S <-- UpdateFunction(S, const_0)
      end for
      S[9] = S[9] ^ K_0,
      S[13] = S[13] ^ K_1
      return S

   procedure ProcessAD(S, Pad(AD))
      d = |AD|/128
      for i = 0 to d - 1 do
         S <-- UpdateFunction(S, AD_i)
      end for
      return S

   procedure Encryption(S, Pad(M), C)
      m = |M|/128
      for i = 0 to m - 1 do
         C_i <-- AESL(S[0] ^ S[1]) ^ S[9] ^ M_i
         S <-- UpdateFunction(S, M_i)
      end for
      return S

   procedure Decryption(S, Pad(C), M)
      c = |C|/128
      for i = 0 to c - 1 do
         M_i <-- AESL(S[0] ^ S[1]) ^ S[9] ^ C_i
         S <-- UpdateFunction(S, M_i)
      end for
      return S

   procedure Finalization(S, |AD|, |M|)
      for i = 0 to 31 do
         S <-- UpdateFunction(S, |AD|, |M|)
      end for
      T = 0
      for i = 0 to 15 do
         T = T ^ S[i]
      end for
      return T
~~~

# Settings Specifications

## Authenticated Encryption

```
Encrypt(msg, ad, key, nonce)
```

The Encrypt function encrypts a message and returns the ciphertext along with an authentication tag that confirms the integrity and authenticity of both the message and any associated data, if present.

Security:

- For a specific key, the nonce MUST NEVER be reused under any circumstances, as doing so could enable an attacker to reconstruct the internal state.

- The key MUST be selected randomly from a uniform distribution.

Inputs:

- msg: the message to be encrypted (its length MUST not exceed P_MAX).

- ad: the associated data to authenticate (its length MUST not exceed A_MAX).

- key: the encryption key (256 bits).

- nonce: the public nonce.

Outputs:

- ct: the ciphertext.

- tag: the authentication tag.

Process:

~~~
K = K_1||K_2
S = 0
ct = {}
S = Initialization(nonce, K_1, K_2)
S = ProcessAD(S, Pad(AD))
S = Encryption(S, Pad(msg), ct)
ct = Truncate(ct, |msg|)
tag = Finalization(S, |ad|, |msg|)
return ct and tag
~~~

## Authenticated Decryption

```
Decrypt(ct, tag, ad, key, nonce)
```

The Decrypt function decrypts the ciphertext, checks the validity of the authentication tag, and returns the message if the tag is verified successfully, or an error if the tag verification fails.

Security:

- If tag verification fails, the scheme MUST NOT output the decrypted ciphertext.

Inputs:

- ct: the ciphertext to decrypt (its length MUST NOT exceed C_MAX).

- tag: the authentication tag.

- ad: the associated data to authenticate (its length MUST NOT exceed A_MAX).

- key: the encryption key.

- nonce: the public nonce.

Outputs:

- Either the decrypted message msg or an error indicating that the authentication tag is invalid for the provided inputs.

Process:

~~~
K = K_1||K_2
S = 0
msg = {}
S = Initialization(nonce, K_1, K_2)
S = ProcessAD(S, Pad(AD))
S = Decryption(S, Pad(ct), msg)
expected_tag = Finalization(S, |ad|, |msg|)
If tag != expected_tag:
   erase msg
   erase expected_tag
   return "verification failed" error
else:
   msg = Truncate(msg, |ct|)
   return msg
~~~

# Setting as a Stream Cipher

```
Keystream(len, key, nonce)
```

The Stream function generates a keystream of variable length by expanding a key and, optionally, a nonce.

Inputs:

- len: Desired length of the keystream in bits.

- key: The HiAE encryption key.

- nonce: The HiAE nonce. If not provided, it defaults to N_MAX bytes of zeros.

Outputs:

- keystream: The resulting keystream.

Process:

~~~
if len == 0:
   return {}
else:
   K = K_1||K_2
   S = 0
   keystream = {}
   S = Initialization(nonce, K_1, K_2)
   msg = Zero(len)
   S = Encryption(S, Pad(msg), keystream)
   return keystream
~~~

The process of generating the keystream is equivalent to encrypting a zero-filled message of length `len`.

# Setting as a Message Authentication Code

HiAE can also be used to construct a Message Authentication Code (MAC), taking a key, nonce, and data as input, and producing a 128-bit authentication tag as output.

```
Mac(data, key, nonce)
```

Security:

- This is the only function where reusing the same (key, nonce) pair with different input data is permitted.

- HiAE-based MACs MUST NOT be used as hash functions, as a known key allows for easy construction of inputs that cause state collisions.

- Unlike MACs built on cryptographic hashes, HiAE-generated tags MUST NOT be used for key derivation, since they are not guaranteed to be uniformly random.

Inputs:

- data: The data to be authenticated (MUST NOT exceed A_MAX in length).

- key: The secret key.

- nonce: The public nonce.

Output:

- tag: The resulting authentication tag.

Process:

~~~
K = K_1||K_2
S = 0
S = Initialization(nonce, K_1, K_2)
S = ProcessAD(S, Pad(data))
tag = Finalization(S, |data|, 0)
return tag
~~~

# Security Considerations

## Classic Setting

HiAE provides `256`-bit security against key recovery and state recovery attacks,
along with `128`-bit security for integrity against forgery attempts. It is important to
note that the encryption security assumes the attacker cannot successfully forge messages
through repeated trials.
Related to the keystream bias attacks, our analysis shows that at least `150`-bit security is guaranteed by HiAE.
Finally, we claim that HiAE is secure in the key-commiting attacks, and we do not claim its security in the everything-commiting setting.

## Quantum Setting

HiAE targets a security strength of `128` bits against key recovery attacks and forgery attacks in quantum setting. We do not claim security against online superposition queries to the cryptographic oracle attacks, as such attacks are highly impractical in real-world applications.

## Attacks Considerations

HiAE is secure against the following attacks:

~~~
  1. Key-Recovery Attack: 256-bit security against key-recovery attacks.
  2. Differential Attack: 256-bit security against differential attacks in the initialization phase.
  3. Forgery Attack: 128-bit security against forgery attacks.
  4. Integral Attack: Secure against integral attacks.
  5. State-recovery Attack:
      * Guess-and-Determine Attack: The time complexity of the guess-and-determine attack cannot be lower than 2^{256}.
      * Algebraic Attack: The system of equations to recover HiAE states cannot be solved with time complexity 2^{256}.

  6. The Linear Bias: at least 150-bit security against a statistical attack.
  7. Key-committing attacks: Secure in the FROB, CMT1, and CMT2 models.
  8. Everything-committing attacks: We do not claim the security of HiAE in CMT3 model.
~~~

The details of the cryptanalysis can be found in the paper {{HiAE}}.

# Implementation Consideration

HiAE is designed to balance the performance of XOR and AES-NI instructions across both ARM and x86 architectures, while being optimized to push performance to its limits.

A complete list of known implementations and integrations is available at https://github.com/Concyclics/HiAE, including reference implementations of HiAE as AEAD Encryption and Decryption, and HiAE-MAC. A comprehensive comparison of HiAE's performance with other high-throughput authenticated encryption schemes on ARM and x86 architectures is also provided.

# IANA Considerations

TBD.

# Test Vectors

## Test Vector 1

~~~ test-vectors
key   : 90bbc6ec798423365146306759d6812e
        37c3740df539834052bd1f46f57d5785

nonce : 381d72b1a195e7f3dc185a35eedb6326

ad    : 9fd7339411b6d56373f4a9697200eeaa
        1d605cbff643b2d25b0c074ae76a7086
        42a31b5359f0b6cde45f36566024017d
        855d3c7ba0ee4dfcfa5446e2beb66800
        598353b273097f5869b5aec9daaf465f
        0c83daad7127a96c7bef4e39a5b63afe

msg   : 3a8db0ad97300500e5b4c9bf630f1e70
        92f81d041fc6709ab5bed45a740e58ae
        9b085c323861321e15fbdd790bfce99d
        f406a114cc11ae81cf82db449033f22c
        3b4e5e74b09192c58c6f3e976b273560
        2dd674f9e8227ab7a555fb3588ee61c4
        3cc038ec51cab2dd39f075a518aa0545
        80793f689bb920400f1b769709d75b46

ct    : ff9fcccf03188954a27c74821b76332b
        d2490761f9d3e3be14613e91ab0af720
        cc63177cc72a63eea503bed4cb70b0c4
        2d38551b47b7bbda52f23374a4feea06
        b8b9c9d3c888935e4a78de02ec329bc8
        66053c77fdabe930f273adc0175802ca
        31b645d1958afc28806843a671347301
        130d23a94f3adee985fb2e60f0d5d024

tag   : 66346519818b4cb2919e61b5f6c28a9b
~~~

## Test Vector 2

~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d

plaintext =
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db
9680ef8b4978631f88032f78e438d56b
5a0dc148674bf513519177840a695fa0
e94f2b32c78e524f9181c776b99ce113
aaa35c11ee51243fe29cc3ec05238cee
72b72039467288d7f34f4dadec2fc096
d21ca7c06dcbff5067c33c6ce6c95a58

ciphertext =
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06
b8b9c9d3c888935e4a78de02ec329bc8
66053c77fdabe930f273adc0175802ca
31b645d1958afc28806843a671347301
130d23a94f3adee985fb2e60f0d5d024
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d
da2089bc5890f2c7ed81d8049e491035
e0cff5abf178e1dfbbcd1ab7ec47ea8d
854419a04f9f8cdd1542c27da97c30e0
bea2f4a7710d72346e0c7369202692ba
5a43850d5a349d4410155f2bc700a655
d2aa57ab9cfa6dd2db0918c4a43a8628

tag =
6bcf434bcbf11824fb40e01ba5023358
~~~

## Test Vector 3
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560

plaintext =
2dd674f9e8227ab7a555fb3588ee61c4

ciphertext =
66053c77fdabe930f273adc0175802ca

tag =
153ba395e9a447f2b34a717dc1608d8a
~~~

## Test Vector 4
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =

plaintext =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db
9680ef8b4978631f88032f78e438d56b
5a0dc148674bf513519177840a695fa0
e94f2b32c78e524f9181c776b99ce113
aaa35c11ee51243fe29cc3ec05238cee
72b72039467288d7f34f4dadec2fc096
d21ca7c06dcbff5067c33c6ce6c95a58
807b91c6ed199ee168eb8e541a4eeaec
6b91acd85dac28c46f6531552e8badae

ciphertext =
d716f4983b0025a57cd4c3c3c94a146d
6cb665a4a5f33032ae3f86dc1a6caed0
5243a1cd70688710da9b9bf9b1e32092
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06
b8b9c9d3c888935e4a78de02ec329bc8
66053c77fdabe930f273adc0175802ca
31b645d1958afc28806843a671347301
130d23a94f3adee985fb2e60f0d5d024
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d
da2089bc5890f2c7ed81d8049e491035
e0cff5abf178e1dfbbcd1ab7ec47ea8d
854419a04f9f8cdd1542c27da97c30e0
bea2f4a7710d72346e0c7369202692ba
5a43850d5a349d4410155f2bc700a655
d2aa57ab9cfa6dd2db0918c4a43a8628
98f538a011f96f60e25662c66df7ccd1
73615cfed071632089825c791163fabe

tag =
250f1f5bdd8d05be98306b42474e7ee3
~~~

## Test Vector 5
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46

plaintext =
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db

ciphertext =
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d

tag =
2e9d4b892ecf8d1c1726d6b2d00a7fb3
~~~

## Test Vector 6
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =

plaintext =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db
9680ef8b4978631f88032f78e438d56b
5a0dc148674bf513519177840a695fa0

ciphertext =
d716f4983b0025a57cd4c3c3c94a146d
6cb665a4a5f33032ae3f86dc1a6caed0
5243a1cd70688710da9b9bf9b1e32092
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06
b8b9c9d3c888935e4a78de02ec329bc8
66053c77fdabe930f273adc0175802ca
31b645d1958afc28806843a671347301
130d23a94f3adee985fb2e60f0d5d024
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d
da2089bc5890f2c7ed81d8049e491035
e0cff5abf178e1dfbbcd1ab7ec47ea8d

tag =
7f6026d8e7d0296dc37f52bad0aa964f
~~~

## Test Vector 7
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =

plaintext =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c

ciphertext =
d716f4983b0025a57cd4c3c3c94a146d
6cb665a4a5f33032ae3f86dc1a6caed0
5243a1cd70688710da9b9bf9b1e32092
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06

tag =
2b84d89eac778e1f6e02938d6bbc6440
~~~

## Test Vector 8
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46

plaintext =
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db
9680ef8b4978631f88032f78e438d56b
5a0dc148674bf513519177840a695fa0
e94f2b32c78e524f9181c776b99ce113
aaa35c11ee51243fe29cc3ec05238cee
72b72039467288d7f34f4dadec2fc096
d21ca7c06dcbff5067c33c6ce6c95a58
807b91c6ed199ee168eb8e541a4eeaec
6b91acd85dac28c46f6531552e8badae
063e75f45713d5bffe631419b1fe051c
90b2f5ed5e1db1cd82e222b06ecf5f74
0dd46864e73d23e5a037fe5236046ec6
b663b3148164e1034703b4b5d21329df
e79243cecf66b3709eb2c2d4b6309a6c
944d8015b16118f864ccad36dfd715c6
69589438be48a85cfa6a30b09bca1c2f
179c44c9fd5cc161296f970846accfaf
0463e7c2ab901fa5fa4f55951a71c431
0d08fa0a65bc6b8e2b029671ae6520b2
c907757497941a92e36f27fde1ec2fee
f429f959e564e710677e8115e3a1c8ac
a93d2140d13bd2b4aafab28be6e17ada

ciphertext =
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d
da2089bc5890f2c7ed81d8049e491035
e0cff5abf178e1dfbbcd1ab7ec47ea8d
854419a04f9f8cdd1542c27da97c30e0
bea2f4a7710d72346e0c7369202692ba
5a43850d5a349d4410155f2bc700a655
d2aa57ab9cfa6dd2db0918c4a43a8628
98f538a011f96f60e25662c66df7ccd1
73615cfed071632089825c791163fabe
5d64c6912c9df6ab0a4ef97b5c848cf4
226172cb26dde45b1f5803b51dcabeb9
088430aafd7ef86f75d161db607b6eae
a93ceff57bee877b8035f081f17fbb0d
38b5258ed3c2a25dd7f1776207e7882d
8321b0f1fb6ef6360616c06945f42035
e069001b5d20b6a1d7573e53fe89cb61
b9dc3e6e4b5b17875550ff2f639fd370
e7b89d24db4613bc1dfdc4c06a62a515
f1c7df93c4ad8596e9016ba98137814d
0dcc3f39306d2a4743d05b429d2b669a
d09ac2f2320653fa84e24a3fc456bb65
2d74782e4d8e7b2412a0c2daeb48db4a

tag =
ed4dacb2fbaa31ca4633509cef1c92fb
~~~

## Test Vector 9
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d

plaintext =
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46

ciphertext =
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06
b8b9c9d3c888935e4a78de02ec329bc8
66053c77fdabe930f273adc0175802ca
31b645d1958afc28806843a671347301
130d23a94f3adee985fb2e60f0d5d024

tag =
a538e4a016862a323841ecbef9855b1d
~~~

## Test Vector 10
~~~
key =
90bbc6ec798423365146306759d6812e
37c3740df539834052bd1f46f57d5785

nonce =
381d72b1a195e7f3dc185a35eedb6326

associated data =
9fd7339411b6d56373f4a9697200eeaa
1d605cbff643b2d25b0c074ae76a7086
42a31b5359f0b6cde45f36566024017d

plaintext =
855d3c7ba0ee4dfcfa5446e2beb66800
598353b273097f5869b5aec9daaf465f
0c83daad7127a96c7bef4e39a5b63afe
3a8db0ad97300500e5b4c9bf630f1e70
92f81d041fc6709ab5bed45a740e58ae
9b085c323861321e15fbdd790bfce99d
f406a114cc11ae81cf82db449033f22c
3b4e5e74b09192c58c6f3e976b273560
2dd674f9e8227ab7a555fb3588ee61c4
3cc038ec51cab2dd39f075a518aa0545
80793f689bb920400f1b769709d75b46
979332e85de4c697d53b3cede5413265
ba71ce552bee963a090cd113e32d597b
c08b631e7029b54564f132493264afec
d67d41016bd73b74e30c87c739e042fa
6ca518dccfcd2133be537df0b72cdc8d
a91d8e14f5c988d8d6109f0ff0e1095c
87213856ee5989acac069c643278f1db
9680ef8b4978631f88032f78e438d56b
5a0dc148674bf513519177840a695fa0
e94f2b32c78e524f9181c776b99ce113
aaa35c11ee51243fe29cc3ec05238cee
72b72039467288d7f34f4dadec2fc096
d21ca7c06dcbff5067c33c6ce6c95a58

ciphertext =
17cd9eac8632514382d4cfc2d93954a2
e3464bd599563524543140c972f65260
453d8f2975609fc41960b20ac522fa73
ff9fcccf03188954a27c74821b76332b
d2490761f9d3e3be14613e91ab0af720
cc63177cc72a63eea503bed4cb70b0c4
2d38551b47b7bbda52f23374a4feea06
b8b9c9d3c888935e4a78de02ec329bc8
66053c77fdabe930f273adc0175802ca
31b645d1958afc28806843a671347301
130d23a94f3adee985fb2e60f0d5d024
dab94f8fd41ccfef27898e5581c4add2
05d3ac44b51df43854cb6a10292ea986
c9725ea6db27695f7ec1c31299e24f8b
e1d44953afb66707179cf873e94a273d
e5fb369ae0314013560e3c597fda5178
c254cf457d3dde55441267fda2145ad5
2a16fbb2d9fa63c6ce8f2175086e5a9d
da2089bc5890f2c7ed81d8049e491035
e0cff5abf178e1dfbbcd1ab7ec47ea8d
854419a04f9f8cdd1542c27da97c30e0
bea2f4a7710d72346e0c7369202692ba
5a43850d5a349d4410155f2bc700a655
d2aa57ab9cfa6dd2db0918c4a43a8628

tag =
6bcf434bcbf11824fb40e01ba5023358
~~~
