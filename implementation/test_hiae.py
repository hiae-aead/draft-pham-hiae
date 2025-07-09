#!/usr/bin/env python3
"""
Test runner for HiAE implementation
Tests against all test vectors from the specification
"""

import sys
from hiae import encrypt, decrypt


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional spaces and newlines) to bytes"""
    return bytes.fromhex(hex_str.replace(' ', '').replace('\n', ''))


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string"""
    return data.hex()


def run_test(test_num: int, key: str, nonce: str, ad: str, msg: str, 
              expected_ct: str, expected_tag: str) -> bool:
    """Run a single test vector"""
    print(f"\nTest Vector {test_num}:")
    
    # Convert inputs
    key_bytes = hex_to_bytes(key)
    nonce_bytes = hex_to_bytes(nonce)
    ad_bytes = hex_to_bytes(ad) if ad else b''
    msg_bytes = hex_to_bytes(msg) if msg else b''
    expected_ct_bytes = hex_to_bytes(expected_ct) if expected_ct else b''
    expected_tag_bytes = hex_to_bytes(expected_tag)
    
    # Test encryption
    ct, tag = encrypt(msg_bytes, ad_bytes, key_bytes, nonce_bytes)
    
    ct_matches = ct == expected_ct_bytes
    tag_matches = tag == expected_tag_bytes
    
    print(f"  Encryption:")
    print(f"    CT matches: {ct_matches}")
    if not ct_matches:
        print(f"      Expected: {expected_ct}")
        print(f"      Got:      {bytes_to_hex(ct)}")
    print(f"    Tag matches: {tag_matches}")
    if not tag_matches:
        print(f"      Expected: {expected_tag}")
        print(f"      Got:      {bytes_to_hex(tag)}")
    
    # Test decryption
    decrypted = decrypt(ct, tag, ad_bytes, key_bytes, nonce_bytes)
    decrypt_success = decrypted is not None
    msg_matches = decrypted == msg_bytes if decrypt_success else False
    
    print(f"  Decryption:")
    print(f"    Success: {decrypt_success}")
    print(f"    Message matches: {msg_matches}")
    if not msg_matches and decrypt_success:
        print(f"      Expected: {msg}")
        print(f"      Got:      {bytes_to_hex(decrypted)}")
    
    # Test tag verification (should fail with wrong tag)
    if len(tag) > 0:
        wrong_tag = bytes([(tag[0] + 1) % 256]) + tag[1:]
        should_fail = decrypt(ct, wrong_tag, ad_bytes, key_bytes, nonce_bytes)
        tag_verify_works = should_fail is None
        print(f"  Tag verification: {'PASS' if tag_verify_works else 'FAIL'}")
    
    return ct_matches and tag_matches and decrypt_success and msg_matches


def main():
    """Run all test vectors"""
    print("HiAE Test Vectors")
    print("=================")
    
    all_passed = True
    
    # Test Vector 1 - Empty plaintext, no AD
    passed = run_test(
        1,
        key="4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
        nonce="a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
        ad="",
        msg="",
        expected_ct="",
        expected_tag="e3b7c5993e804d7e1f95905fe8fa1d74"
    )
    all_passed &= passed
    
    # Test Vector 2 - Single block plaintext, no AD
    passed = run_test(
        2,
        key="2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
        nonce="7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
        ad="",
        msg="55f00fcc339669aa55f00fcc339669aa",
        expected_ct="66fc201d96ace3ca550326964c2fa950",
        expected_tag="2e4d9b3bf320283de63ea5547454878d"
    )
    all_passed &= passed
    
    # Test Vector 3 - Empty plaintext with AD
    passed = run_test(
        3,
        key="9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
        nonce="3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
        ad="394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
        msg="",
        expected_ct="",
        expected_tag="531a4d1ed47bda55d01cc510512099e4"
    )
    all_passed &= passed
    
    # Test Vector 4 - Rate-aligned plaintext (256 bytes)
    passed = run_test(
        4,
        key="6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
        nonce="9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
        ad="",
        msg="ffffffffffffffffffffffffffffffff" * 16,
        expected_ct="""2e28f49c20d1a90a5bce3bc85f6eab2f
e0d3ee31c293f368ee20e485ec732c90
45633aa4d53e271b1f583f4f0b208487
6e4b0d2b2f633433e43c48386155d03d
00dbf10c07a66159e1bec7859839263a
c12e77045c6d718ddf5907297818e4ae
0b4ed7b890f57fa585e4a5940525aa2f
62e4b6748fa4cd86b75f69eff9dfd4df
9b0861ae7d52541ff892aa41d41d55a9
a62f4e4fefb718ee13faca582d73c1d1
f51592c25c64b0a79d2f24181362dfbb
352ac20e1b07be892a05b394eb6b2a9d
473c49e6b63e754311fdbb6c476503f0
a3570482ece70856ae6e6f8d5aa19cc2
7b5bce24ee028e197ed9891b0a54bf02
328cb80ceefc44b11043d784594226ab""",
        expected_tag="f330ae219d6739aba556fe94776b486b"
    )
    all_passed &= passed
    
    # Test Vector 5 - Rate + 1 byte plaintext
    passed = run_test(
        5,
        key="3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
        nonce="6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c",
        ad="6778899aabbccddeef00112233445566",
        msg="cc339669aa55f00fcc339669aa55f00f" * 16 + "cc",
        expected_ct="""5d2d2c7f1ff780687c65ed69c08805c2
69652b55f5d1ef005f25300d1f644b57
e500d5b0d75f9b025fee04cfdf422c6c
3c472e6967ac60f69ff730d4d308faed
beac375ae88da8ab78d26e496a5226b5
ffd7834a2f76ecc495a444ffa3db60d8
ec3fb75c0fcaa74966e1caec294c8eb7
a4895aa2b1e3976eb6bed2f975ff218d
c98f86f7c95996f03842cee71c6c1bc5
f7b64374e101b32927ed95432e88f8e3
8835f1981325dbcec412a4254e964c22
cf82688ee5e471c23a3537de7e51c288
92e32c565aa86ab708c70cf01f0d0ee9
781251759893d55e60e0d70014cb3afb
45e0821ba6e82e0f490ff2efef2f62c5
7332c68c11e6ed71ef730b62c3e05edf
f6""",
        expected_tag="1122dc5bedc7cad4e196f7227b7102f3"
    )
    all_passed &= passed
    
    # Test Vector 6 - Rate - 1 byte plaintext
    passed = run_test(
        6,
        key="8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f",
        nonce="4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a",
        ad="",
        msg="00000000000000000000000000000000" * 15 + "000000000000000000000000000000",
        expected_ct="""322970ad70b2af87676d57dd0b27866d
8c4f0e251b5162b93672de1ab7aaf20c
d91e7751a31e19762aeea4f3811657a3
06787ff4ebc06957c1f45b7fd284ef87
f3a902922999895ff26fddbd5986eac5
ef856f6ae270136315c698ec7fe5a618
8aa1847c00a3a870044e8d37e22b1bca
b3e493d8ae984c7646f2536032a40910
b6c0f317b916d5789189268c00ef4493
bcb5fb0135974fa9bec299d473fdbf76
f44107ec56b5941404fd4b3352576c31
3169662f1664bd5bccf210a710aa6665
fb3ec4fa3b4c648411fd09d4cada31b8
947fdd486de45a4e4a33c151364e23be
6b3fc14f0855b0518e733d5ea9051165
25286bb2d6a46ac8ef73144e2046f9""",
        expected_tag="7eb4461a035fe51eaf4a1829605e6227"
    )
    all_passed &= passed
    
    # Test Vector 7 - Medium plaintext with AD
    passed = run_test(
        7,
        key="5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c",
        nonce="8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d",
        ad="""95a6b7c8d9eafb0c1d2e3f5061728394
a5b6c7d8e9fa0b1c2d3e4f60718293a4
b5c6d7e8f90a1b2c3d4e5f708192a3b4
c5d6e7f8091a2b3c4d5e6f8091a2b3c4""",
        msg="""32e14453e7a776781d4c4e2c3b23bca2
441ee4213bc3df25021b5106c22c98e8
a7b310142252c8dcff70a91d55cdc910
3c1eccd9b5309ef21793a664e0d4b63c
83530dcd1a6ad0feda6ff19153e9ee62
0325c1cb979d7b32e54f41da3af1c169
a24c47c1f6673e115f0cb73e8c507f15
eedf155261962f2d175c9ba3832f4933
fb330d28ad6aae787f12788706f45c92
e72aea146959d2d4fa01869f7d072a7b
f43b2e75265e1a000dde451b64658919
e93143d2781955fb4ca2a38076ac9eb4
9adc2b92b05f0ec7""",
        expected_ct="""ca3b18f0ffb25e4e1a6108abedcfc931
841804c22a132a701d2f0b5eb845a380
8028e9e1e0978795776c57a0415971cf
e87abc72171a24fd11f3c331d1efe306
e4ca1d8ede6e79cbd531020502d38026
20d9453ffdd5633fe98ff1d12b057edd
bd4d99ee6cabf4c8d2c9b4c7ee0d219b
3b4145e3c63acde6c45f6d65e08dd06e
f9dd2dde090f1f7579a5657720f348ae
5761a8df321f20ad711a2c703b1c3f20
0e4004da409daaa138f3c20f8f77c89c
b6f46df671f25c75a6a7838a5d792d18
a59c202fab564f0f""",
        expected_tag="74ba4c28296f09101db59c37c4759bcf"
    )
    all_passed &= passed
    
    # Test Vector 8 - Single byte plaintext
    passed = run_test(
        8,
        key="7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
        nonce="2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
        ad="",
        msg="ff",
        expected_ct="51",
        expected_tag="588535eb70c53ba5cce0d215194cb1c9"
    )
    all_passed &= passed
    
    # Test Vector 9 - Two blocks plaintext
    passed = run_test(
        9,
        key="4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b",
        nonce="7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f",
        ad="""c3d4e5f60718293a4b5c6d7e8fa0b1c2
d3e4f5061728394a5b6c7d8e9fb0c1d2
e3f405162738495a6b7c8d9eafc0d1e2""",
        msg="""aa55f00fcc339669aa55f00fcc339669
aa55f00fcc339669aa55f00fcc339669""",
        expected_ct="""03694107097ff7ea0b1eac408fabb60a
cd89df4d0288fa9063309e5e323bf78f""",
        expected_tag="2a3144f369a893c3d756f262067e5e59"
    )
    all_passed &= passed
    
    # Test Vector 10 - All zeros plaintext
    passed = run_test(
        10,
        key="9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
        nonce="5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e",
        ad="daebfc0d1e2f405162738495a6b7c8d9",
        msg="00000000000000000000000000000000" * 8,
        expected_ct="""eef78d00c4de4c557d5c769e499af7b9
8e5ad36cdaf1ff775a8629d82751e97e
8f98caa0773fe81ee40266f0d52ddbbe
f621504863bf39552682b29748f8c244
5c176cd63865732141edc59073cff90e
5996a23a763f8dd058a6a91ada1d8f83
2f5e600b39f799a698228b68d20cd189
e5e423b253a44c78060435050698ccae""",
        expected_tag="59970b0b35a7822f3b88b63396c2da98"
    )
    all_passed &= passed
    
    print("\n" + "="*50)
    if all_passed:
        print("ALL TESTS PASSED!")
        return 0
    else:
        print("SOME TESTS FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(main())