# Crypto roxoxor

문제의 지문을 보면 나의 이름으로 로봇을 실행시킬 수 있다고 한다. 

```python
Rick got a robot named "XORius" as a gift by his parents which 
activates with a key, in user manual it was written - 
"we suggest you to use your name is X factor for ROBO ^_^" 

so Rick followed the user manual, his bot was working fine and 
now started saying 
"2506110631060d103c5a15582036045b3c075734640015580d10531e0d1c134a2f"

But now Rick has fear of his parents and he wants your help to 
understand his ROBO
```

X Factor는 Rick이고 암호화 데이터는 "2506110631060d103c5a15582036045b3c075734640015580d10531e0d1c134a2f" 이다. 

XOR 시키면 플래그를 얻을 수 있다.

```python
X = "Rick"
A = [0x25,0x06,0x11,0x06,0x31,0x06,0x0d,0x10,0x3c,0x5a,0x15,0x58,0x20,0x36,0x04,0x5b,0x3c,0x07,0x57,0x34,0x64,0x00,0x15,0x58,0x0d,0x10,0x53,0x1e,0x0d,0x1c,0x13,0x4a,0x2f]

for i in range(0,len(A)):
    A[i] ^= ord(X[i%len(X)])

for i in A:
    print(chr(i)),
```

FLAG : **wormcon{n3v3r_g0nn4_6iv3_y0u_up!}**
