# Crypto exclusive

지문에서 얻을 수 있는 힌트는 없다.

```python
SO EXCLUSIVE. MUCH ELITE. SUCH WOW.
```

2개의 파일 chall.py와 out.txt가 주어진다.

```python
cipher = a1adabc2b7acbbffb5ae86fee8edb1aeabc2e8a886a986f5e9f0eac2bbefeaeaeaf986fee8edb1aeab%
```

- Python Code

    ```python
    #!/usr/bin/env python3
    import os

    def splitit(n):
    	return (n >> 4), (n & 0xF)

    def encrypt(n, key1, key2):
    	m, l = splitit(n)
    	e = ((m ^ key1) << 4) | (l ^ key2)
    	return e

    FLAG = open('flag.txt').read().lstrip('wormcon{').rstrip('}')
    alpha = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'

    assert all(x in alpha for x in FLAG)

    otp = int(os.urandom(1).hex(), 16)
    otpm, otpl = splitit(otp)

    print(f"{otp = }")
    cipher = []

    for i,ch in enumerate(FLAG):
    	if i % 2 == 0:
    		enc = encrypt(ord(ch), otpm, otpl)
    	else:
    		enc = encrypt(ord(ch), otpl, otpm)
    	cipher.append(enc)

    cipher = bytes(cipher).hex()
    print(f'{cipher = }')

    open('out.txt','w').write(f'cipher = {cipher}')
    ```

코드를 요약하면, 다음과 같다. 

1. 출제자는 플래그 파일을 로드한다. 
    1. 플래그 포맷은 제외하고 로드시킨다.
    2. 로드한 데이터는 암호화에 이용된다.
2. OTP의 범위는 0x00 - 0xFF이다. 
    1. OTP 번호 하나가 추출되면 상위 1바이트, 하위 1바이트로 분할된다. 상위 1바이트는  otpm, 하위 1바이트는 otpl로 칭한다.
    2. 분할 된 데이터는 플래그 인덱스 짝수, 홀수에 따라 서로 다른 루틴을 가지게 된다.
        1. 짝수일 경우, otmp, otpl순서 
        2. 홀수일 경우,  otpl, otmp순서
3. 플래그 길이(포맷 제외): 41바이트 
4. 연산 끝나면 암호화 파일('out.txt')를 생성한다.

문제를 풀 때, 복호화 연산을 생각하려고 했는데 생각보다 시간이 오래걸릴 거 같다는 판단이 들었다. 그래서 문제를 들여다볼 당시에 이런 마인드로 접근하였다.

출제자는 이 문제를 제작할 때, 마음에 드는 숫자 0x00 - 0xFF중 하나를 선택했을 것이다. 그리고 output을 만들어 둔뒤, 참가자들에게 코드를 전달할 때는 랜덤을 쓴 것 처럼 눈속임을 했을 것이라고 생각했다.

출제자가 검수를 꼼꼼히 했는지는 모르겠지만, 41번 횟수를 하나의 암호 알고리즘을 통해 2개의 조건문 분기로 연산을 수행하면 중복되는 랜덤 OTP값, 전혀 사용되지 않은 랜덤 OTP값이 있을 거라 생각했다. 

그래서 사용되지 않은 OTP값을 추려내기 위해 다음과 같은 방법을 사용하였다. 소스코드를 보면 보안의 취약점이 보이게 된다. OTP는 단 한번만 생성되고, OTP의 헥사값을 상위,하위로 쪼개어 진행되는데 이때 생성된 OTP만 암호화 알고리즘에 관여한다. 즉, OTP가 한번 생성되면 그 값이 무엇이든 간에 100번이든 1000번이든 똑같은 암호화 알고리즘과 직면하게 된다는 것이다.

그렇다면, 첫번째 암호화 데이터 0xa1을 목표치로 잡았을 때 OTP 0x00-0xFF 중 어떤 데이터가 암호화 알고리즘을 거쳐 0xa1에 도달할 수 있는지 확인하는 작업을 거치게 된다면 아주 쉽게 사용될 "**가능성**"이 있는 값을 알 수 있게 된다.

첫 번째 바이트만 기준으로 했을 때 마주할 수 있는 후보는 다음과 같았다.

```python
otp = [145, 144, 147, 146, 149, 148, 151, 150, 153, 152, 192, 195, 194, 197, 196, 199, 198, 201, 200, 203, 202, 205, 204, 207, 206, 209, 208, 211, 210, 213, 212, 215, 214, 217, 216, 219, 224, 227, 226, 229, 228, 231, 230, 233, 232, 235, 234, 237, 236, 239, 238, 241, 240, 243, 242, 245, 244, 247, 246, 249, 248, 251]
```

 

두번째 바이트만 기준으로 했을 때 마주할 수 있는 후보는 다음과 같았다.

```python
otp =  [217, 201, 249, 233, 153, 204, 236, 205, 237, 206, 254, 238, 207, 239]
```

이 둘의 교집합만 구하게 된다면, 우리는 사용할 수 있는 OTP의 범위가 눈에 뛰게 줄어들 것이다.

이 방법을 이용하여 결국, OTP는 단 하나 217만이 41바이트 모두를 만족하게 되었다. 

실시간으로 작성했기에 코드는 다소 정신없지만, 플래그를 얻기엔 충분한 코드이다.

- Code

    ```python
    import os
    import string 

    flag = string.digits+string.ascii_letters+"_"

    # global

    real_flag = [0xa1,0xad,0xab,0xc2,0xb7,0xac,0xbb,0xff,0xb5,0xae,0x86,0xfe,0xe8,0xed,0xb1,0xae,0xab,0xc2,0xe8,0xa8,0x86,0xa9,0x86,0xf5,0xe9,0xf0,0xea,0xc2,0xbb,0xef,0xea,0xea,0xea,0xf9,0x86,0xfe,0xe8,0xed,0xb1,0xae,0xab]
    even_flag = []
    odd_flag = []

    even_otp_guess = [] 
    odd_otp_guess =[]
    intersection_otp = [153, 249, 233, 201, 204, 236, 205, 237, 206, 238, 207, 239, 217, 254] # first byte && second byte's intersection otp number is default

    def splitit(n):
    	return (n>>4) , (n&0xF)

    def encrypt(flag_char, key1, key2):
    	m, l = splitit(flag_char)
    	e = ((m^key1) << 4 | (l ^ key2))
    	return e

    '''
    # delete
    otp_tmp = []
    for i in range(0,256):
    	otp_tmp.append(int(i))
    #print(flag)
    #print(otp_tmp)
    '''

    flag_length=41 

    #even_flag_guess = []

    def chk_even():
    	k = 0
    	for i in flag: # flag byte guess
    		for j in intersection_otp: # otp
    			#print(type(j)) # int
    			otpm,otpl = splitit(int(j))
    			enc = hex(encrypt(ord(i), otpm, otpl))
    			enc = int(enc,16) 
    		
    			if enc == even_flag[k]: # 0xa1
    				even_otp_guess.append(j)
    				k += 1
    				if k > len(even_flag):
    					break
    				#first_flag_guess.append(i)	
    				#exit(0)
    			else:
    				continue

    #print(f'otp =  {otp_guess}')
    #print(f'first byte flag guess : {first_flag_guess}')
    		
    #print("new otp candidate!")	
    #otp =  [145, 144, 147, 146, 149, 148, 151, 150, 153, 152, 192, 195, 194, 197, 196, 199, 198, 201, 200, 203, 202, 205, 204, 207, 206, 209, 208, 211, 210, 213, 212, 215, 214, 217, 216, 219, 224, 227, 226, 229, 228, 231, 230, 233, 232, 235, 234, 237, 236, 239, 238, 241, 240, 243, 242, 245, 244, 247, 246, 249, 248, 251, 254]

    # second pOC
    # enc == 0xad 

    #second_flag_guess =[]

    def chk_odd():
    	k = 0
    	for i in flag:
    		for j in intersection_otp:
    			#print(type(j)) # int
    			otpm,otpl = splitit(int(j))
    			enc = hex(encrypt(ord(i), otpl, otpm))
    			enc = int(enc,16) 
    		
    			if enc == odd_flag[k]: # 0xa1
    				odd_otp_guess.append(j)
    				k += 1
    				if k > len(odd_flag):
    					break
    				#second_flag_guess.append(i)	
    				#exit(0)
    			else:
    				continue

    #print(f'otp =  {otp_guess}')
    #print(f'second byte flag guess : {second_flag_guess}')		

    def init():

    	# even [i%2]
    	# odd [! i%2]
    	for i in range(0,len(real_flag)):
    		if i % 2 == 0:
    			even_flag.append(real_flag[i])
    		else:
    			odd_flag.append(real_flag[i])

    if __name__ == '__main__':
    	init()
    	chk_even()
    	chk_odd()
    	intersection_otp = list(set(even_otp_guess).intersection(odd_otp_guess))
    	print(f'result otp is {intersection_otp}')

    	result_otp = int(217)
    	print(f'type result_otp => {type(result_otp)}')
    	otpm, otpl = splitit(result_otp)
    	print(f'otpm => {otpm}')
    	print(f'otpl => {otpl}')
    	k = 0
    	l = 0
    	i = 0
    	get_flag = []
    	for loop in range(0,41):
    		print(f"Flag index {loop} finding...")
    		for _flag in flag:
    			if loop % 2 == 0: # even
    				enc = hex(encrypt(ord(_flag),otpm, otpl))
    				print("even check")
    				enc = int(enc,16)
    				if enc == real_flag[loop]:
    					get_flag.append(_flag)
    					break	
    #exit(0)
    			else: # loop is odd
    				enc = hex(encrypt(ord(_flag),otpl, otpm))
    			
    				enc = int(enc,16)
    				if enc == real_flag[loop]:
    					get_flag.append(_flag)
    					break
    				
    # max = 41bytes
    print("wormcon{"),
    for i in range(0, len(get_flag)):
    	print(get_flag[i].strip(' '), end=' ')
    print("}")
    ```

![exclusive-flag](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/cryptography/exclusive/.resource/exclusive-flag.png)
