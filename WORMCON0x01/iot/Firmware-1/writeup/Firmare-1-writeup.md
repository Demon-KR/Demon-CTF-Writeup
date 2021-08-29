# IOT - Firm #1

Mips 파일이 하나 주어졌고, 지문은 다음과 같다.

```c
Me and my time are trying to get the admin access of the gate 
but we are not able to get into it you have to find the secret password 
and what is the "kernel version" so that we can attack it.
```

펌웨어는 'binwalk' 어플리케이션을 통해 데이터를 추출할 수 있다. 

![binwalk](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/iot/Firmware-1/.resource/binwalk.png)

_Frim-1.bin.extracted가 하나의 디스크라고 보면 된다.

![Firm1_extract](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/iot/Firmware-1/.resource/Firm1_extract.png)

처음에 접근할 때는 너무 어렵게 접근하였다. secret password라고 하고, admin에 관련된 게이트라고 해서 Mips 리버싱문제인줄 알고 바이너리로 의심되는 파일들을 다 찾기 시작했다. 

그러다 문제 풀이자가 많아지는 것을 보고, 생각보다 단순하게 접근하면 되구나 싶어 /etc/shadow에 존재하는 root의 해시를 브루트포싱하기로 결정하였다. 

아쉽게도, 대회 당시는 John the ripper의 디폴트 딕셔너리 파일로 실행시켜두고 다른 문제들을 풀고 있었다. 아무리 시간이 지나도 패스워드가 출력되지 않았다. 그래서 잘못 된 방식으로 접근했는가보다 하고 포기하고 다른 문제들을 계속 풀었다. 

대회가 끝나고, 풀이자에게 물어보니 John the ripper로 푸는게 의도한 것이였고, rockyou.txt를 사용했어야한다고 한다. John the ripper를 사용한 적이 많이 없어서 당연히 rockyou.txt로 진행하겠지 싶었다. 개인적으로 이런 문제는 펌웨어 문제로 내면 안될 거 같다. 

어쨌든, John the ripper로 root 패스워드를 찾으면 다음과 같다.

![John-The-Ripper](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/iot/Firmware-1/.resource/john-the-ripper.png)

커널 버전은 Firmware파일을 헥사에디터로 열람하면 바로 확인할 수 있다.

FILE: [https://drive.google.com/file/d/1tIdtg2T5DdkawgUs-zTF6Ttl3C1PeDQ_/view?usp=sharing](https://drive.google.com/file/d/1tIdtg2T5DdkawgUs-zTF6Ttl3C1PeDQ_/view?usp=sharing)
