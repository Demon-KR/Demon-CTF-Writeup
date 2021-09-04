# SSTF - Secure Enough

# Type

Reverse Engineering 

# **Material**

One Binary file

One Network packet file 

# Description

```c
I made my protocol. 
I think it is really safe.
```

# Summary

1. The packet can communicate with 7001 port.
2. MD5 data is depends on time stamp.
3. The timestamp is weak methodology if it uses on the srand().
4. This binary uses AES256 CBC mode. That's why players should find the Key and IV into the binary logic first. 
5. The author shared one of RSA public key. It meant players can decrypt data via this key. (RSA_public_decrypt function is vulnerable) because can get n and e value. 
6. The packer number 4, 6, 8, 10, 18, 20, 22, and 24 is communicated data via ELF file.

# Structure #1 Network

This binary communicated with one of ports which is 7001.

```c
__int64 __fastcall connect_network(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned int fd; // [rsp+18h] [rbp-28h]
  __int16 s; // [rsp+20h] [rbp-20h]
  uint16_t v6; // [rsp+22h] [rbp-1Eh]
  int v7; // [rsp+24h] [rbp-1Ch]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  fd = socket(2, 1, 0);
  memset(&s, 0, 0x10u);
  s = 2;
  v6 = htons(7001u);
  inet_pton(2, (const char *)a1, &v7);
  if ( !connect(fd, (const struct sockaddr *)&s, 0x10u) )
    return fd;
  perror("connect");
  return 0xFFFFFFFFLL;
} 
```

# Structure #2 RSA

The binary has one RSA public key. The methodology was set via openssl framework. The function name is BIO_new_mem_buf. It will be make a memory about BIO structure. 

```c
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA214EFGCpMbQhB4uRo7P9\n"
"FAajAfvz7ianshjD44IvZeZHeEYTfa1zONbjYGK2lw/0v+xZ/Em4M9sPOSGlsPcr\n"
"vG3O9/XKM0+he05Lh8nedtMnpOQgxFhwJNbdKR3SYzsH8+JziLHAmKQmlmH8FBiE\n"
"reGsshAhICrz8GGDCjDg7Aam4wKj0HY6hfj8zUYjAf2MxoozWIYFmjSXI2xwp6Kq\n"
"Uqhac9W0nnQkToe+vtBjlcPowRV9WViNIB2msE6afe+YqKVSYNizbEXSbmocsA+A\n"
"job4i1u8LAtdd4zF5gmGuKCJITiMMglakHzwosXXfbejIaJlpfC6sx4xIu6nkx6Y\n"
"lQIDAQAB\n"
"-----END PUBLIC KEY-----",
```

# Structure #3 MD5 & AES

Some of .bss datas will use MD5 calculator. Following the md5 function, values('tmp1', 'tmp2', and 'tmp7') are important data. Later, these temp values will be renamed based on their own real behaviour. 

```c
__int64 __fastcall md5(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 target; // ST08_8
  char v5; // [rsp+20h] [rbp-70h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  target = a3;
  v6 = __readfsqword(0x28u);
  MD5_Init(&v5, a2);
  MD5_Update(&v5, a1, (signed int)a2);
  MD5_Update(&v5, &tmp1, 32LL);
  MD5_Update(&v5, &tmp2, 32LL);
  MD5_Update(&v5, &tmp7, 32LL);
  MD5_Final(target, &v5);
  return __readfsqword(0x28u) ^ v6;
} 
```

```c
__int64 __fastcall sub_170F(__int64 a1)
{
  md5("A", 1LL, &tmp3);
  md5("BB", 2LL, &tmp4);
  md5("CCC", 3LL, &tmp5);
  return md5("DDDD", 4LL, &tmp6);
}
```

If players can catch this code below, they recognise what is value's real intentions.

```c
__int64 __fastcall sub_17D2(__int64 a1, unsigned int a2, __int64 a3)
{
  __int64 v3; // ST08_8
  __int64 v4; // rax
  unsigned int v6; // [rsp+24h] [rbp-1Ch]
  int v7; // [rsp+28h] [rbp-18h]
  unsigned int v8; // [rsp+2Ch] [rbp-14h]
  __int64 v9; // [rsp+30h] [rbp-10h]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v3 = a3;
  v10 = __readfsqword(0x28u);
  v9 = EVP_CIPHER_CTX_new();
  v4 = EVP_aes_256_cbc();
  v7 = EVP_EncryptInit_ex(v9, v4, 0LL, &key, &iv);
  v7 = EVP_EncryptUpdate(v9, v3, &v6, a1, a2);
  v8 = v6;
  v7 = EVP_EncryptFinal_ex(v9, (signed int)v6 + v3, &v6);
  v8 += v6;
  EVP_CIPHER_CTX_free(v9);
  return v8;
}
```

```c
__int64 __fastcall sub_170F(__int64 a1)
{
  md5("A", 1LL, &key); // changed
  md5("BB", 2LL, &tmp4); // connected key
  md5("CCC", 3LL, &iv); // changed
  return md5("DDDD", 4LL, &tmp6); // IDK? FAKE
}
```

The tmp4 and tmp6 did not have any connection on the logic. In other words, &key and &tmp4 is set. Hence, the &iv and &tmp6 also set. 

# How to find the timestamp?

This is quite simple thing. It is because, the author shared to players about one packet file called by out.pcap. This file has only 28 packets. Fortunately, the packet time difference is not messy.

Let me share my timestamp via the packet.

 

![arrival-time](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/SSTF/Rev/secure-enough/.resource/arrival-time.png)

The arrival time(Human date) can replace Unix Timestamp instead.

![epoch-time](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/SSTF/Rev/secure-enough/.resource/epoch-time.png)

Therefore, we can use the Epoch time is '1624347317'.

# How to make encrypt data?

Next step, players need to check how to make encrypt data via full binary execution. Look at the this logic instead. Please be careful, the binary is just example. Therefore, your purpose is get some algorithm via the binary no need think about what is binary has data deeply. 

```c
unsigned __int64 __fastcall goto_Encrypt(int a1)
{
  __int64 src; // [rsp+18h] [rbp-48h]
  int v3; // [rsp+20h] [rbp-40h]
  __int64 packet_buf; // [rsp+24h] [rbp-3Ch]
  int v5; // [rsp+2Ch] [rbp-34h]
  __int64 buf; // [rsp+30h] [rbp-30h]
  __int64 v7; // [rsp+38h] [rbp-28h]
  __int64 v8; // [rsp+40h] [rbp-20h]
  __int64 v9; // [rsp+48h] [rbp-18h]
  unsigned __int64 v10; // [rsp+58h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  src = ' eM eviG';
  v3 = 'yeK';
  packet_buf = 0LL;
  v5 = 0;
  LOBYTE(packet_buf) = 3;
  memcpy((char *)&packet_buf + 1, &src, 0xBu);  // Give Me Key : example(fake)
  buf = 0LL;                                    // 32bytes : init
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  AES256_Encrypt((__int64)&packet_buf, 0xCu, (__int64)&buf);// buf : 32bytes
  write(a1, &buf, 0x20u);
  return __readfsqword(0x28u) ^ v10;
}
```

# Where is exist real packet?

As you know, players offered one packet file by the author. Although the packet already encrypted, do not need scared when you analysis. Because, we can check binary data from the packet. 

The packer number 4, 6, 8, 10, 18, 20, 22, and 24 has data packet.  

Anyway, let us check first tmp1 and tmp2. 

```c
__int64 __fastcall md5(__int64 plainData, __int64 len, __int64 a3)
{
  __int64 target; // ST08_8
  char v5; // [rsp+20h] [rbp-70h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  target = a3;
  v6 = __readfsqword(0x28u);
  MD5_Init(&v5, len);
  MD5_Update(&v5, plainData, (signed int)len);
  MD5_Update(&v5, &tmp1, 32LL); // We are still do not know
  MD5_Update(&v5, &tmp2, 32LL); // We are still do not know
  MD5_Update(&v5, &tmp7, 32LL); // We are still do not know
  MD5_Final(target, &v5);
  return __readfsqword(0x28u) ^ v6;
}

// a3 is &tmp1 and &tmp2
__int64 __fastcall KeyGenerator(__int64 data, __int64 a2, __int64 a3)
{
  unsigned int timestamp; // eax
  __int64 v4; // rdx
  _QWORD *v5; // rcx
  __int64 v6; // rdx
  int rand_data; // [rsp+18h] [rbp-E8h]
  int another_rand_data; // [rsp+1Ch] [rbp-E4h]
  char v10; // [rsp+20h] [rbp-E0h]
  char v11; // [rsp+80h] [rbp-80h]
  __int64 v12; // [rsp+E0h] [rbp-20h]
  __int64 v13; // [rsp+E8h] [rbp-18h]
  unsigned __int64 v14; // [rsp+F8h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  timestamp = time(0LL);
  srand(timestamp);
  rand_data = rand();
  MD5_Init(&v10, a2);
  MD5_Update(&v10, &rand_data, 4LL);
  MD5_Final(&v12, &v10);
  v4 = v13;
  *(_QWORD *)data = v12;
  *(_QWORD *)(data + 8) = v4;
  another_rand_data = rand();
  MD5_Init(&v11, &v10);
  MD5_Update(&v11, &another_rand_data, 4LL);
  MD5_Final(&v12, &v11);
  v5 = (_QWORD *)(data + 16);
  v6 = v13;
  *v5 = v12;
  v5[1] = v6;
  return __readfsqword(0x28u) ^ v14;
}
```

We already got the timestamp. It's value is a 1624347317. but python code no exist srand function into the random module. 

- Code

    ```python
    from ctypes import c_int, c_uint
    import hashlib  # md5 
    import struct

    import binascii
    timestamp = 1624347317

    # ref
    # https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c
    def srand(seed):
        srand.r = [0 for _ in range(34)]
        srand.r[0] = c_int(seed).value
        for i in range(1, 31):
            srand.r[i] = (16807 * srand.r[i - 1]) % 2147483647
        for i in range(31, 34):
            srand.r[i] = srand.r[i - 31]
        srand.k = 0
        for _ in range(34, 344):
            rand()

    def rand():
        srand.r[srand.k] = srand.r[(srand.k - 31) % 34] + srand.r[(srand.k - 3) % 34]
        r = c_uint(srand.r[srand.k]).value >> 1
        srand.k = (srand.k + 1) % 34
        return r

    srand(timestamp)
    tmp1 = hashlib.md5(struct.pack('<I', rand())).digest()
    tmp2 = hashlib.md5(struct.pack('<I', rand())).digest()
    generate = tmp1+tmp2
    print(type(generate))
    # b'\xa3\xe6\xf4\x84\xd7\x86Z\xb1\x05n\x15\x83<t\x8b\xed\xb6\x89\xc0a?\xa1\x14j5\xf1)yzw\x05\x14'

    # PoC (via packet 04)
    test = "01a3e6f484d7865ab1056e15833c748bedb689c0613fa1146a35f129797a7705142e9041559d7b0efb5cca1ec10310091de88fe3d3b85df5862be216ae07c13a25b3554692c441e9a3574275a6b3f3cb7f70e4c4967e7f893fdff2d8279f70d53a9265aea14c86b560e97e813cec1d03ef819d276d0e7e1c0809dabb367dc85c387a2ebc79e2740a89f1b119c7ee978d436b6389cc2be163670f4fb82dd96801cf5d9626f8b903c039b06e7d0d8cfeceb2c21ec6054843628499bd12a741d2d35bdd4361f07148cae759833a4a1ea15d6874c21cafa4934eab3debff36252149a11407bf4196cf18242937757ae408856f1e654a25d9d75849df2b664c6886ee97d5a940d73faf9625b709beda7c1d0f171ca061fe3bf0e6232592d817f9a4a6a60000"
    md5_test = binascii.unhexlify(test[2:2 + len(generate*2)])

    if md5_test == generate:
        print("Great")

    else:
        exit(0)
    ```

How can we get data, tmp7? The tmp7 only handled by two addresses. 

![tmp7](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/SSTF/Rev/secure-enough/.resource/tmp7.png)

The feature allows we to recognise that it is a 'tmp7' associated with RSA. Then, the 'tmp7' length is 32 also.

```c
signed __int64 __fastcall sub_1561(int a1)
{
  signed __int64 result; // rax
  char src; // [rsp+10h] [rbp-210h]
  char s; // [rsp+110h] [rbp-110h]
  _BYTE v4[7]; // [rsp+111h] [rbp-10Fh]
  unsigned __int64 v5; // [rsp+218h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(&s, 0, 0x103u);
  if ( read(a1, &s, 0x103u) >= 0 )
  {
    if ( s == 2 )
    {
      RSA_decrypt_option((__int64)v4, 0x100u, (__int64)&src);
      memcpy(&tmp7, &src, 0x20u); // 32
      result = 0LL;
    }
    else
    {
      puts("Not a valid response packet");
      result = 0xFFFFFFFFLL;
    }
  }
  else
  {
    perror("Failed to receive");
    result = 0xFFFFFFFFLL;
  }
  return result;
}

signed __int64 __fastcall RSA_decrypt_option(__int64 a1, unsigned int len, __int64 a3)
{
  signed __int64 result; // rax
  __int64 v4; // [rsp+8h] [rbp-28h]
  __int64 v5; // [rsp+28h] [rbp-8h]

  v4 = a3;
  v5 = get_RSA_PUBKEY();
  if ( v5 )
    result = (unsigned int)RSA_public_decrypt(len, a1, v4, v5, 1LL);
  else
    result = 0xFFFFFFFFLL;
  return result;
}

__int64 get_RSA_PUBKEY(void)
{
  __int64 v1; // [rsp+8h] [rbp-18h]
  __int64 v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0LL;
  v2 = BIO_new_mem_buf(
         "-----BEGIN PUBLIC KEY-----\n"
         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA214EFGCpMbQhB4uRo7P9\n"
         "FAajAfvz7ianshjD44IvZeZHeEYTfa1zONbjYGK2lw/0v+xZ/Em4M9sPOSGlsPcr\n"
         "vG3O9/XKM0+he05Lh8nedtMnpOQgxFhwJNbdKR3SYzsH8+JziLHAmKQmlmH8FBiE\n"
         "reGsshAhICrz8GGDCjDg7Aam4wKj0HY6hfj8zUYjAf2MxoozWIYFmjSXI2xwp6Kq\n"
         "Uqhac9W0nnQkToe+vtBjlcPowRV9WViNIB2msE6afe+YqKVSYNizbEXSbmocsA+A\n"
         "job4i1u8LAtdd4zF5gmGuKCJITiMMglakHzwosXXfbejIaJlpfC6sx4xIu6nkx6Y\n"
         "lQIDAQAB\n"
         "-----END PUBLIC KEY-----",
         0xFFFFFFFFLL);
  if ( v2 )
    return PEM_read_bio_RSA_PUBKEY(v2, &v1, 0LL, 0LL);
  perror("Failed to create key BIO");
  return 0LL;
}
```

Do you remember? We already used packet 4. This packet can see the md5 value (tmp1+tmp2)

Vulnerabilty in this problem arise where decrypting is carried out with public key. 

By the way, we can find chiper data into the packet file.

Look at the packet 6. As you know from the packet 4 

The packet 6 is RSA cipher. 

```c
__int64 __fastcall RSA_encrypt_option(__int64 buf, __int64 len, __int64 a3)
{
  __int64 result; // rax
  __int64 output; // [rsp+8h] [rbp-28h]
  __int64 v5; // [rsp+28h] [rbp-8h]

  output = a3;
  v5 = get_RSA_PUBKEY();
  if ( v5 )
    result = (unsigned int)RSA_public_encrypt((unsigned int)len, buf, output, v5, 1LL);// buf is tmp2
  else
    result = 0xFFFFFFFFLL;
  return result;
} 
```

Actually, the original RSA decryption using by this methodology.

RSA decryption algorithm is below.

M = c ^ d mod n (d is private key)

pow(c,d,n)

However. I just have public key. 

So, I can use c ^ e mod n instead. because the binary using RSA_public_decrypt(). 

Let us try to get e, n, m, and md53 value through the Public key.

- Code

    ```python
    pubKey = RSA.importKey(open('sstf.pub','r').read())

    e = pubKey.e
    n = hex(pubKey.n)
    print(f'e is {e}')
    print(f'n is {n}')

    m = pow(c,e,int(n,16))
    print(type(m))
    print(hex(m)) # RSA_encryption_option(&tmp2,32,&v4)
    print(len(hex(m)))
    md53 = binascii.unhexlify(hex(m)[-64:])
    print(md53)
    ```

# Answer

- Code

    ```python
    from ctypes import c_int, c_uint
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES
    import hashlib  # md5 
    import struct
    import binascii

    from Crypto.Util.py3compat import b
    timestamp = 1624347317

    # ref
    # https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c
    def srand(seed):
        srand.r = [0 for _ in range(34)]
        srand.r[0] = c_int(seed).value
        for i in range(1, 31):
            srand.r[i] = (16807 * srand.r[i - 1]) % 2147483647
        for i in range(31, 34):
            srand.r[i] = srand.r[i - 31]
        srand.k = 0
        for _ in range(34, 344):
            rand()

    def rand():
        srand.r[srand.k] = srand.r[(srand.k - 31) % 34] + srand.r[(srand.k - 3) % 34]
        r = c_uint(srand.r[srand.k]).value >> 1
        srand.k = (srand.k + 1) % 34
        return r

    srand(timestamp)
    tmp1 = hashlib.md5(struct.pack('<I', rand())).digest()
    tmp2 = hashlib.md5(struct.pack('<I', rand())).digest()
    generate = tmp1+tmp2
    md51 = generate
    print(type(generate))
    # b'\xa3\xe6\xf4\x84\xd7\x86Z\xb1\x05n\x15\x83<t\x8b\xed\xb6\x89\xc0a?\xa1\x14j5\xf1)yzw\x05\x14'

    # PoC (via packet 04)
    test = "01a3e6f484d7865ab1056e15833c748bedb689c0613fa1146a35f129797a7705142e9041559d7b0efb5cca1ec10310091de88fe3d3b85df5862be216ae07c13a25b3554692c441e9a3574275a6b3f3cb7f70e4c4967e7f893fdff2d8279f70d53a9265aea14c86b560e97e813cec1d03ef819d276d0e7e1c0809dabb367dc85c387a2ebc79e2740a89f1b119c7ee978d436b6389cc2be163670f4fb82dd96801cf5d9626f8b903c039b06e7d0d8cfeceb2c21ec6054843628499bd12a741d2d35bdd4361f07148cae759833a4a1ea15d6874c21cafa4934eab3debff36252149a11407bf4196cf18242937757ae408856f1e654a25d9d75849df2b664c6886ee97d5a940d73faf9625b709beda7c1d0f171ca061fe3bf0e6232592d817f9a4a6a60000"
    md5_test = binascii.unhexlify(test[2:2 + len(generate*2)])
    md52 = md5_test

    if md5_test == generate:
        print("Great")

    else:
        exit(0)

    # RSA decrypt
    # c^d mod n (fermat's little theorom)
    # pow(c,d,n)

    #c = "020f4b82b9d771a2625de1339269ead8599308a5119f3c8a3eb2e266f04210c2ac7e5657072ecd5fb777a99a8d57d94e39fa7001dd926ac42e4e9c944cd086868605d59db718caf0738f9983575119e4ae63f84c7a274eba7b39b9dc19a749a9bca7bead0aa75ea8f2c34a48dda8a4812e933249e945f66858785947d95168154b18e44f0ffa4f3c0a336ee2fc72f6b0aa1deeba5cd4646e68ae591923dc2894597862a753c3f86409cc19b8b5070de08fdab340618e6fb9370d95bf07670d76cdf320d5bd3bf10c26ec89f47956a4e6f850f751d7480c82cb25f7a48ba167d207d7a3836c7dee679a7ac1e004e0399598994e7542d63e65eb24b41158c66728720000"
    #The reason packet 4 [0:2] is dummy
    # last \x00 is need to remove !
    c = 0x0f4b82b9d771a2625de1339269ead8599308a5119f3c8a3eb2e266f04210c2ac7e5657072ecd5fb777a99a8d57d94e39fa7001dd926ac42e4e9c944cd086868605d59db718caf0738f9983575119e4ae63f84c7a274eba7b39b9dc19a749a9bca7bead0aa75ea8f2c34a48dda8a4812e933249e945f66858785947d95168154b18e44f0ffa4f3c0a336ee2fc72f6b0aa1deeba5cd4646e68ae591923dc2894597862a753c3f86409cc19b8b5070de08fdab340618e6fb9370d95bf07670d76cdf320d5bd3bf10c26ec89f47956a4e6f850f751d7480c82cb25f7a48ba167d207d7a3836c7dee679a7ac1e004e0399598994e7542d63e65eb24b41158c6672872

    # d is private key.
    # but, I have public key
    # so Just check e and n values.
    pubKey = RSA.importKey(open('sstf.pub','r').read())

    e = pubKey.e
    n = hex(pubKey.n)
    print(f'e is {e}')
    print(f'n is {n}') 

    m = pow(c,e,int(n,16))
    print(type(m))
    print(hex(m)) # RSA_encryption_option(&tmp2,32,&v4)
    print(len(hex(m)))
    md53 = binascii.unhexlify(hex(m)[-64:])
    print(md53)

    h = hashlib.md5()
    h.update(b'A')
    h.update(md51)
    h.update(md52)
    h.update(md53)
    key = h.digest()

    h = hashlib.md5()
    h.update(b'BB')
    h.update(md51)
    h.update(md52)
    h.update(md53)
    key += h.digest()

    h = hashlib.md5()
    h.update(b'CCC')
    h.update(md51)
    h.update(md52)
    h.update(md53)
    iv = h.digest()

    print(f'key is {key}')
    print(f'iv is {iv}')

    # packet 8 
    # data + padding(\x00)
    # no need on exploit I think

    # packet 10
    # 64 bytes so need padding
    '''
     *((_BYTE *)&a3 + (signed int)AES256_Decrypt((__int64)&buf, 64u, (__int64)&a3)) = 0;
    '''
    enc = 'dc014f2266d9368dbd6fb5d3fa1d675cc2172ae703872afbadc94dc8cbc8afcda7c1177253fe51114041ad0103bbb86500000000000000000000000000000000'

    aes = AES.new(key, AES.MODE_CBC, iv)
    print(aes.decrypt(binascii.unhexlify(enc)))
    ```
