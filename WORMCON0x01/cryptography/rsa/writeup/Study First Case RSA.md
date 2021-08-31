# [KR ver] Study case RSA  [wormcon CTF 2021]

# Prolog

대회 당시 풀지 못하였다. 크립토를 조금 더 경험하고 싶어 마음을 가다듬고 문제를 들여다보았다. 

p,q에 대한 기초부터 차근차근 이틀간 공부를 하고 마침내 플래그를 볼 수 있었다. 내 인생 처음으로 RSA를 복호화해본 날이다.!

사실, 이 문제 하나 이해했다고 다른 문제를 내가 풀 수 있을거라는 확신은 없다. 😱

RSA나 기타 암호학문제는 많은 경험이 쌓여야 할 거 같다. 

푸는데 이틀 걸렸다. 🥵

---

대회 끝나고, 출제자한테 RSA문제는 어떻게 만들 수 있는건지도 물어봤는데 Condition 하나는 꼭 지켜야한다고 했다.

```python
"if 1 < m < n"

m means 'message'. 
n means 'candidate modular'

찾아보니 아래의 공식때문에 저 룰이 필수적으로 만족되어야 한다.
```

![encrypt logic](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/encrypt%20logic.png)

---

## Let we see the source code first

소스코드를 살펴보도록 하자. Crypto 관련 문제들은 소스코드가 정말 짧다는 것이 특징인 것 같다. 

```python
#!/usr/bin/env python3
from Crypto.Util.number import *

FLAG = open('flag.txt', 'rb').read() # 출제자만 알고 있는 이 플래그를 이용한다

bits = 512
e = 65537 # 자연로그가 아니라 encryption에서 따온 것이라 함 , 65537 역시 소수이다.
# RSA에서 자주 사용되는 숫자라고 하니 기억해두자.
p = getPrime(bits) # 아직은 이놈이 뭐하는 놈인지 모른다고 가정해보자.
q = getPrime(bits)
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi) # 나머지 연산 
hint = 2*d*(p-1337)

m = bytes_to_long(FLAG) # plain text.
c = pow(m, e, n) # encrypt encrypt encrypt session

print(f"n = {hex(n)}")
print(f"e = {hex(e)}")
print(f"c = {hex(c)}")
print(f"hint = {hex(hint)}")
```

다들 아시다시피 RSA는 Asymmetric Key이다. 기본적으로 다들 알고 있는 지식은 대칭키는 키가 하나이고 비대칭키는 일단 키가 2개이다. 그리고, 단 한사람 '저는 개인키를 소지하고 있습니다' 라고 말할 수 있는 사람만 이 암호를 복호화해서 열람할 수 있다.

그나저나, 이 문제에서는 p와 q가 직접적으로 노출되어 있지 않다. 

그래서 처음에 Factor를 추출해주는 사이트를 이용해보았었다. 하지만, 값이 너무 커서 그런지 사이트에서 소수(p 그리고 q)가 발견되지 않았다. 

512 * 512를 하게되면, 1024Bits(128Bytes). 엄청 큰 값이 나오게 된다. 😇

이렇게 생각해본 이유는 다음과 같이 테스트 해봤기 때문이다. 학생 때는 몰랐던 수학의 신비로움을 우연히 발견했다. 갑자기 수학이 재밌어진다.

```python
>>> 444 * 44
19536 => Length : 5 [444(n=3) + 44(n=2)]
>>> 444 * 444 
197136 => Length : 6
>>> 444 * 4444
1973136 => Length : 7
```

gerPrime 함수 이름만 보면 직관적으로 소수를 구한다는 것을 예측할 수는 있지만, 내부 기능이 궁금해졌다.

---

## getPrime 함수

- Study case

    > getPrime(N, randfunc=None)
    getPrime(N:int, randfunc:callable):long Return a **random** N-bit prime number.

    [https://pythonhosted.org/pycrypto/Crypto.Util.number-module.html](https://pythonhosted.org/pycrypto/Crypto.Util.number-module.html)

    [https://github.com/pycrypto/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/number.py#L169](https://github.com/pycrypto/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/number.py#L169)

    ```python

    def getPrime(N, randfunc=None): # 현재 문제에서 N은 512
        """getPrime(N:int, randfunc:callable):long
        Return a random N-bit prime number.
        If randfunc is omitted, then Random.new().read is used.
        """
        if randfunc is None:
            _import_Random() 
    ''''
    _def _import_Random():
    	global Random, StrongRandom
      from Crypto import Random
      from Crypto.Random.random import StrongRandom
    ''''

            randfunc = Random.new().read # 주석과 현 문제 소스코드를 동시에 비교해보면, randfunc는 None이다.
    # 그러므로, Random 클래스를 이용하여 임의의 랜덤 값을 만들 수 있다.

                                 # 512 대입 
        number=getRandomNBitInteger(N, randfunc) | 1   # 무슨 값인지 모르겠지만 반환 된 값과 무조건 1하고 OR 연산을 취해준다
        while (not isPrime(number, randfunc=randfunc)): # randfunc는 up to computer calc
            number=number+2 # number += 2 계속 2씩 더해주게 되는군 2의배수를 기준점으로 해야해서 그런거 같음
        return number
    ```

    **Random.new().read**를 사용해본 경험이 없었기에 이를 적용했을 때 어떤 값이 반환되어 나오는지 알 필요가 있다고 생각했다.

    ```python
    >>> from Crypto import Random
    >>> from Crypto.Random.random import StrongRandom
    >>> randfunc = Random.new().read

    >>> print(randfunc)
    <bound method _UrandomRNG.read of <Crypto.Random._UrandomRNG object at 0x10b6aec50>>
    >>> print(dir(randfunc))
    ['__call__', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__func__', '__ge__', '__get__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__self__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__']
    >>> print(type(randfunc))
    <class 'method'>

    ```

    형태가 method이다. method 자체를 getRandomNBitInteger에 대입하고 있음을 알 수 있다.

    ```python
    number=**getRandomNBitInteger**(N, **randfunc**) | 1
    ```

    ```python
    randfunc = Random.new().read # object (class is method)
    number=getRandomNBitInteger(N, randfunc) | 1

    # But, why this method also randfunc value's default is None? 
    def getRandomNBitInteger(N, randfunc=None):
        """getRandomInteger(N:int, randfunc:callable):long
        Return a random number with exactly N-bits, i.e. a random number
        between 2**(N-1) and (2**N)-1.
        If randfunc is omitted, then Random.new().read is used.
        This function is for internal use only and may be renamed or removed in
        the future.
        """
        value = getRandomInteger (N-1, randfunc)  # return 54 (If bits=511) 
        value |= 2L ** (N-1)                # Ensure high bit is set
        assert size(value) >= N  # checker
        return value

    # go to the getRandomInterger function instead
    def getRandomInteger(N, randfunc=None):
        """getRandomInteger(N:int, randfunc:callable):long
        Return a random number with at most N bits.
        If randfunc is omitted, then Random.new().read is used.
        This function is for internal use only and may be renamed or removed in
        the future.
        """
        if randfunc is None:
            _import_Random()
            randfunc = Random.new().read # random object generated 

        S = randfunc(N>>3) # S is random value 
    # If N is 512, the N>>3 == N / 8(2^3)
    # So, S is 512 / 8 => 64
        odd_bits = N % 8  # N requires a multiple value of 8.
    # odd_bits = 512 % 8 == 0
    # so skip route 1. 

    # If N is 511, the N>>3 is 7
    # So, S is 7. 
    # However, odd_bits is not Zero
    # Can go route 1 instead 
       # [+] randfunc(1) equal 0x00-0xFF
    	 # [+] In this case, the odd_bits is 7 therefore, the result is 1 
       # if ord(randfunc(1)) is 95 
       # the char will be set 47 ( 95 >> 1 ) 

      # 47 + 7 = 54 

        #[route 1]
        if odd_bits != 0:
            char = ord(randfunc(1)) >> (8-odd_bits)
            S = bchr(char) + S # goto the route 2 also

        # [route 2]
        value = bytes_to_long(S)
        return value
    ```

    gerPrime ← getRandomNBitInteger ← getRandomInteger

    - If the bits set is 511, return getPrime's length is 154
    - If the bits set is 512, return getPrime's length is 154
    - if the bits set is 512 (again), return getPrime's length is 155

    결국, 소수는 랜덤으로 뽑히기 때문에 길이 역시 달라짐을 알수 있다. 사실, RSA에서는 이 부분은 중요하지 않은거같다. 핵심은 p*q를 해서 n이라는 값을 도출할 수 있는 것.   

    이로써 getPrime의 전체 기능을 알게 되었다. 무야호 🥳

    랜덤 데이터의 값이 **소수가 나올 때 까지** 무한반복시켜 나온 반환 값이므로 무조건 소수가 된다. 

---

## What is 'n' ?

- Study case

    드디어 p와 q에 대한 것은 인지하였으니, n에 대해 알아보도록 하자. 

    몇시간 전만해도 n이 왜 p*q인지 몰랐는데, 조금전에 곱셈의 규칙을 파악하게 됨으로써 p*q를 해야하는 이유를 알 것도 같다...

    외울필요가 없는 것이다. 정확한 이해를 한지 모르겠지만, 내가 현재 이해하기로는 p의 바이트 수와 q의 바이트 수를 합치는 것과 둘의 리턴값은 같은 선상에 놓아야하는 것이면서도 아닌 것이기도 한 형태인거같다. 

    $\phi(N) = (p-1)(q-1)$ 

    문제라고 생각하지말고 극단적인 예시를 들어보면, $(p-1)(q-1)$값을 일단 모른다고 가정하고 N이 10인것은 알고 있을 때, $\phi(10) = 1,3,7,9$ 총 4개가 나오게 되니까, $(p-1)(q-1)$은 무조건 4가 된다라고 리버싱할 수 있다.

    그럼 p와 q는 추측할 수 있다. 하지만, 중요한건 p,q는 무조건 소수여야한다는 것. 

    p=3, q=3일 경우, 4가 성립하게 된다.

    하지만, 이 공식을 아는 동생에게 검수받아봤는데 $p^2$  형태가 되면 euler phi$(\phi)$계산이 달라지게 된다고 한다. 이해는 나중에하고 일단 동생에게 들은 것을 참고하면, 다음과 같다.

    ${p^(k-1)} * (p-1)$

    wikipedia를 보면 다음과 같이 적혀있다. "두 개의 서로 다른 소수를 고른다"

    ![prime explanation](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/prime%20explanation%201.png)

## What is 'e'?

- Study case

    우선 형식적인 말로 풀어보자면, $e$는 **반드시 $\phi(N) > e$  &&   $\phi(N)$과 서로소여야한다.**

    현재 문제에서 e값을 65537로 Set 해두었음을 알 수 있고, 이 말인 즉슨 $\phi(N) > 65537$ 이라는 것이다. 

    다시 말해, $(p-1)(q-1)$ 은 65538개 이상의 서로소를 가지고 있게 된다. 

## What is 'phi'?

- Study case

    위에서의 공식 $(p-1)(q-1)$ 자체가 $\phi$ 이다. $N$은 이 코드 라인에는 관여하지 않는다.

## What is 'd'?

- Study case

    일단 문제 코드를 다시 살펴보자.

    ```python
    d = inverse(e, phi)
    ```

    inverse 함수 역시 library에 적용되어 있는 함수이다. 

    ```python
    # u is e
    # v is phi
    def inverse(u, v):
        """inverse(u:long, v:long):long
        Return the inverse of u mod v.
        """
        u3, v3 = long(u), long(v) # casing first
        u1, v1 = 1L, 0L
             => I don't know why just set hardcoded(1 and 0) " u1 and v1 "

        while v3 > 0:
            q=divmod(u3, v3)[0] # return format tuple via quotient, remainder
            u1, v1 = v1, u1 - v1*q
            u3, v3 = v3, u3 - v3*q
        while u1<0:
            u1 = u1 + v
        return u1
    ```

    d는 개인키라고 불리운다. 이름만 들어도 아주아주 중요한 녀석임을 인지할 수 있다. 이 값을 구하기 위해 역함수를 이용했음을 코드를 통해 식별할 수 있다. 

    $(e * d) \% \phi(n) = 1$   이라는 공식을 기억해야한다. 작은 숫자로 계산하여 흐름을 파악하면 좋을 거 같아, 이런 시나리오를 만들었다. 

    > $e = 4 , d = ? , \phi(n) = ?$ 라고 가정해봤을 때, 반환값이 1이 나와야한다.

    나올 수 있는가? 나올 수가 없다 왜냐하면 짝수 4와 3만 나머지 연산해서는 1이라는 값이 나올 수 있지만 d가 1일 수는 없을 것이고 (암호화의 의미가 사라지니까), 4는 소수가 아니기 때문이다.

    그럼 기억할 게 하나 더 생긴다. e 역시 짝수값이 나오면 안된다. 

    > 출제자는 임의의 숫자를 생각없이 준게 아니다.

    $e=3, d=?, \phi(n)=?$ 은 1이 나올 수 있다.

    $\phi(n)$=16 일 때, (3*d) % 16 = 1 ⇒ 3d % 16 = 1 ⇒ $d=11$

    이 상황일 때 개인키는 11이 된다고 생각하면 된다.

    자 그렇다면, 이렇게 값이 작은경우 침입자도 쉽게 나머지 연산에 쓰이는 값을 알아낼 수 있겠지만, 어마어마하게 큰 숫자를 조합하여 메시지를 암호화 할 경우는 손쉽게 해결할 수 없을 것이다. 그러므로 '단 한사람에게'만 키를 준다고 표현하는 거 같았다.

# Do u know what is author's intend?

- Study case

    소스코드 분석은 막바지에 다다랐다. 이 코드를 보자. 

    ```python
    hint = 2*d*(p-1337)
    ```

    왜 이것이 힌트일까? 1337이 가지는 의미를 알아야한다. 

    l337? 으로 준 것은 아닐거다.. 

    머리를 정리해보는 시간을 가졌다.

    1. 1337은 소수이다.
    2. d는 개인키이면서, $(e*d)  \mod\ \phi(N) = 1$ 에서 가지고 놀 수 있다.
    3. 개인키를 출제자가 알려주지는 않았다. 
    4. 하지만, hint 값을 알고 있으니 d를 구할 수 있는 계기를 준 것이다. 
    5. p도 +1337하면 구해진다.

    자 여기서 의문점, d와 p 두개 변수가 공백으로 되어있다. 단순한 사칙연산으로 추측할 수가 없다. 

    그러니 아직 무야호~ 할 때가 아니다. 

    여기서 잘 생각해야한다. d를 먼저 구하러 갈 것인가, p를 먼저 구하러 갈 것인가? 나는 p를 선택했다.

    왜냐하면, d는 $inverse(e,\phi)$의 결과값인데, $\phi$를 구하는 공식이 $(p-1)(q-1)$이기 때문이다.

    과연 나의 선택은 옳았던 것일까. 

    역원에 대해 검색 검색 검색을 거치다 Fermat's little theoreom에 대해 공부하게 되었다. 아하. 이 녀석이 바로 RSA에 꼭 필요한 개념이었다. 

    그림으로 대신한다.

    첫번째 그림은  $p\ mod\$    연산 취했을 때 0이 나온다. 하지만, Wrong이라고 적어두었다. 왜냐, $p$가 2일 경우 3번 곱하는 건 불가능하기 때문이다. 

    ![Fermet](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/Fermet.png)

    두번째 그림은 $p$가 3일 경우이다. 물음표에서 보면, 이 역시 5번 곱하기 때문에 $p-1$에 성립하지 않음을 알 수 있다. 하지만! $a^(3-1)$의 경우 $2*2 \equiv 1 (4\ mod\ p)$ 가 성립하게 된다.

    p가 3, a=5일 경우, $5*5 \equiv 1\ (25\ mod\ 3)$

    p가 3, a=1337일 경우, $1337 * 1337 \equiv 1\ (1787569\ mod\ 3)$

    **p가 3, a=5315313일 경우, $5315313\ *\ 5315313\ \equiv\ 0\ ( 28252552287969\ mod\ 3)$ 왜 이건 성립하지 않는걸까? 3배수이기 때문이다.** 

    p가 3, a=4일 경우, $4\ * 4\ \equiv\ 1\ (16\ mod\ 3)$ a는 짝수인데 1이 나온다? a값은 짝수여도 상관없다는 얘기다.

    ![Fermet2](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/Fermet%202.png)

    그렇다면, p가 마냥 소수라고 무조건 다 사용할 수 있는게 아니다. 

    **If isPrime(p) && p % i ≠ 0 일때만 가능한 것이다.**

    하지만, $2 ^ (p-1) \equiv 1$이 나왔다고 해서 1000000% p는 소수다라고 생각하면 또 안된다고 한다. 알다가도 모르겠다.

    다시 문제로 돌아와보자. 

    ```python
    hint = 2*d*(p-1337)
    ```

    hint = 2d * (p-1337)

    ```python
    hint = 0x7acdc2f1c0acd1fb471f7804a984b962206babbbc8aba1c6a06757b1a10ba3941e5d9d5a1f19b8d9ed9facb48f8f0beda5366ed62c77303a5749e96f1cb820fd0d4d4e7ac1fc15207ae36f9a5aa0fdd9240605277d5ba51dee5075186fbea7340a5b2d09d82e025485ecedd7c505265e81c57db7ce72e722c0179f71669413c54fced2b3663b2171e38554d00e876c67b5d221bea6b1c7345fe1ae024ffdd72afd12f79522ac96932f6505d9ce8e7abad89182bcb7911b6a1dc7054c7a42b304
    ```

    d ??

    p ?? 

    미지수 하나를 통해 p를 구할 수 있다. 미지수를 x로 두면,

    $x * x^-1 = x^(1-1)\ = x^0=1\ \equiv x*y  \equiv 1$이 되는 공식이 있다. 

    이를 이용하여 GCD(Greatest Common Divisor)를 사용할 수 있다고 한다. 

    최대공약수를 이용한 공식은 $GCD(a,p)\ \equiv 1 (a\ \not\equiv\ p,a\ \not\equiv\ 0)$ 

# Let me try solve the problem

- Exploit

    소스코드를 보면, 핵심은 p,q라고 생각할 수 있지만 나는 핵심을 c = pow(m, e, c)로 두고 접근해보았다.

    어쩌면 당연할수도 암호화 결과 데이터를 만들어내는 핵심부분이니까.

    페르마 소 정리를 다시 상기해보면, 평문을 가지고 암호화하는 방식이 이거였다. 

    $C = M^e\ mod\ n$

    그런데 여기서는 c방식이 pow(x,y,z)로 되어있다. pow를 거듭제곱으로만 알고 있었는데 3번째 인자까지 합해지면, z는 mod에 이용될 수 있다.

    ![pow](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/pow.png)

    그럼, 이 간단한 한줄로 수식으로 보면 약간 어질어질할수도 있는 연산을 만들어버릴 수 있다. 

    암호화와 복호화는 공통적으로 사용하는게 있다. 그건 바로 n이다. n은 곧, $(p*q)$

    지금은 비록 내가 p와 q를 별도로 알진 못하지만! **출제자는 n을 친절하게 알려줬다.** 

    자, 암호문을 복호화 하는 과정은? 

    $M = C^d\ mod\ n$

    출제자가 준 데이터는?

    ```python
    1. n값 aka q*q
    2. e값 나의 친구에게 던져줄 공개키에 들어가는 숫자
    3. c값 나의 친구가 나에게 공개키를 이용하여 만들어준 암호화 데이터 
    4. 친절하게 알려준 hint 2*d*(p-1337)
    ```

    M = pow(c, ?, n) 

    d를 구하는 방법 

    $(e*d)\ mod\ (p-1)(q-1) \equiv 1$

    e 이미 알고 있음 

    d 모름

    (p-1)(q-1)은 모르는데 p*q는 알고 있음

    - Simple Example

        p=5 q=7일 때 

        5*7=35

        4*6=24 

        sub ⇒ 11

        p=11, p=13일 때 

        11 * 13 = 143

        10 * 12 = 120 

        sub ⇒ 23

        이건 선 넘은 분석이라고 판단되었었음.

    p와 q는 무조건 소수여야함. p-1, q-1은 합성수여야함. 

    합성수라는 것은? 최대공약수가 만들어질 수 있다는 것임. 

    GCD는 일단 친절하게 파이썬 라이브러리에서 제공해줌.

    [https://www.programcreek.com/python/example/92185/Crypto.Util.number.GCD](https://www.programcreek.com/python/example/92185/Crypto.Util.number.GCD)

    4번은 youtube를 통해 페르마 소정리를 배울 때 밑을 줘야한다고 배웠다.

    ```python
    hint = 2*d*(p-1337)
    ```

    hint는 h로 칭한다

    $a^h = a^(2*d*p-1337)\ mod\ n$

    d로 되어있는 것은 복호화를 진행하는데 도움을 주겠다는 것이다. 

    d를 e로 교체하게 되면, 암호화를 진행하는데 도움을 주겠다는 것이 된다. 

    n은 공통이었고 페르마 정리에서 M과 C의 위치가 바뀌었고 의도에 따라 e 혹은 d값을 썼다. 

    지금은 d에서 역연산을 취해줘야하기 때문에 리버싱 관점으로 생각해본다면 e*d 하면 1이 되면서 무용지물 되어버린다.

    직접 써가면서 연산을 수행해보았다. 어우 수학공식을 몇년만에 작성해서 어질어질했다.

    ![handwriting #1](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/handwriting%201.png)

    ![handwriting #2](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/rsa/.resource/handwriting%201.png)

    이렇게 하면 p값을 구할 수 있게 된다. 

    이제 원리를 알았으니 코드로 구현해보자.

    - Exploit Code

        ```python
        from Crypto.Util.number import *

        # Author already offered these datas
        n = 0xced9347557a5d6f88e3a506517ad051aff9c1a2ee8a1ac27f3dd74c58ac1c5bc2e2ba7ae2aba617497c5204d3933d9a941cf9af61d8308d760cad984567fa725f35510f6944dce3306687b49138c1eda555cd1f1a0c5fbf10b47ca0aa2afca13083a02f59281a2087d8b277fa43ad187dbc84d37f276c997b9ed456c1601256d
        e = 0x10001
        c = 0xd5d4bc7f461ab02dddb1c3d911bfeee35837a787b02f09d45f5c29e122d784bf5ee97e1ace3a320130fb8747c40292a8503613b674280ab7b64163e9a2ab8a39dfba55d2032d67f1d3fe6389881f8c4145c5b7eb8d83caaa6ebebad021f668a83434d7d48a249f5e8e23828b1aa9402c8b88eab9c48e035a9997bdcc4b48479
        hint = 0x7acdc2f1c0acd1fb471f7804a984b962206babbbc8aba1c6a06757b1a10ba3941e5d9d5a1f19b8d9ed9facb48f8f0beda5366ed62c77303a5749e96f1cb820fd0d4d4e7ac1fc15207ae36f9a5aa0fdd9240605277d5ba51dee5075186fbea7340a5b2d09d82e025485ecedd7c505265e81c57db7ce72e722c0179f71669413c54fced2b3663b2171e38554d00e876c67b5d221bea6b1c7345fe1ae024ffdd72afd12f79522ac96932f6505d9ce8e7abad89182bcb7911b6a1dc7054c7a42b304

        # goal to find p 
        p = 0 
        a = 0

        tmp = pow(2,e,n) # 2 ^ e mod n 
        a = pow(tmp,hint,n) # (2^e mod n) ^ hint mod n 
        print(f'a = {hex(a)}')
        # 4^hint % n 
        #  = 4 ^ (p-1) mod n
        #  = (4 ^ p) * (4 ^ -1336) mod n 
        # 'mod n' should be staying same position everyday
        chk = pow(4,1336,n)  # switch 2 and e position 

        a = a*chk % n 
        p = GCD(a-1,n)
        print(f'p = {hex(a)}')

        # q = n / p  # this signal will be return float data 

        # The RSA need to set INTEGER!
        q = n // p 
        print(f'q = {hex(q)}') # Type Error : 'float' object cannot be interpreted as an integer

        if n == p*q:
            print("great")

        # The encrypt logic is below
        # C = M ^ e mod n 
        # e is public

        # The decrypt logic is below
        # M = C ^ d mod n
        # d is private

        # Let's find d
        # if (e*d) mod (p-1)(q-1) is 1 is correct
        # the (p-1)(q-1) is phi
        phi = (p-1)*(q-1)

        # If wants to get d
        # just inverse!
        d = inverse(e,phi)

        M = pow(c,d,n)
        print(type(M))
        #print(bytes_to_long(M)) # object of type 'int' has no len() => because typo..
        print(long_to_bytes(M))
        ```

    ref. [https://www.youtube.com/watch?v=kGUlfVpIfaQ](https://www.youtube.com/watch?v=kGUlfVpIfaQ)

    ref. [https://www.youtube.com/watch?v=uhXOkoXtULI](https://www.youtube.com/watch?v=uhXOkoXtULI)
