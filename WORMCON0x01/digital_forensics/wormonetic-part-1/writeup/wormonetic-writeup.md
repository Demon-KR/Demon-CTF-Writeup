지문을 보면, 한 인턴이 의심스러워 그의 피시 디스크를 덤프 떠두었는데 인턴이 해커와 접촉할 때 사용한 이름과 접촉을 시도한 해커의 이메일 주소를 알아내라고 한다.

```c
Welcome to our organisation wormonetics. 
Our R&D team is working on a secret project Project Σ. 

But due to an insider threat our Project is at risk 
[ As per the law of corporate yes he is Intern ]. 

After doing a lot of analysis we got the final person who is responsible 
but we find strong evidence so we capture the image of his PC Disk and 
for further Investigation we need your help in return 
we will provide you points 😄

So now you have to find what name our intern is using for c
ontacting the Hackers and it will be great 
if you also find the email address of whom he is contacting. 

Flag : wormcon{name_email}
```

주어진 메모리 덤프는 Windows였으며, 한 유저의 Local 데이터들을 분석하다보면 이 회사는 Thunderbird 프레임워크를 이용하여 이메일을 주고 받을 수 있음을 알 수 있다. 

Thunderbird 특성 상 SENT, TRASH 등의 파일이 평문 저장 되어 있는데 Sent 데이터를 열람하면 인턴이 사용한 닉네임과 인턴과 메일을 주고받은 해커의 이메일 주소를 알 수 있다.

FLAG: wormcon{[harry_hackwithdark@outlook.com](mailto:harry_hackwithdark@outlook.com)}
