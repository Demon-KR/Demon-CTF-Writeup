# Missing Ranger
```
My friend RangerCP has gone out for Night Out, but now, after 2 days, he has still not come home. We are not even able to contact him and by searching a lot we only get to know about his email address. Now you have to find his location (upto three decimals). Email : r1pp3rS0ul@gmail.com

Flag Format:- wormcon{latitude_longitude}

Author: RCP
```
RangerCP 라는 사람이 집에 돌아오지 않는다며 이메일만 알려주었다. 해당 이메일로 아무 메일이나 보내보았다.

![image](https://user-images.githubusercontent.com/44149738/131459005-7a4e24f4-0dbc-42f8-b920-40678ea9e9b1.png)

이메일을 보내자 위와 같이 답장이 왔다. 본인이 있는 장소라며 사진을 하나 첨부했다. 처음엔 스테가노그래피인가 싶었는데 OSINT 카테고리에, 위도 경도가 플래그임을 미루어보아 사진을 통해 위치를 특정하는 문제가 맞다고 생각했다. 아래는 원본 이미지다.

![unnamed](https://user-images.githubusercontent.com/44149738/131460856-7a57925b-6091-451b-afab-800683930148.jpg)

원본 이미지의 메타데이터를 가장 먼저 분석했다. 그러나 별다른 정보는 없었다. 구글에서 제공하는 이미지 검색도 이용해 보았으나 찾기가 어려웠다. 여기서 주원이형이 세상 캐리를 해버렸는데, 아래 사이트를 통해 다른 여러 포털에서도 검색해보니 동일한 이미지를 찾았다고 한다.

https://www.aware-online.com/en/osint-tutorials/reverse-image-search/

주원이 형은 이 중에 bing 에서 찾았다고 했다. 그 이름은 `Parco Della Resistenza`.

![image](https://user-images.githubusercontent.com/44149738/131461408-89abca0d-68cf-4309-a249-4d5e6d06be65.png)

거의 다 왔다고 생각했지만 생각보다 쉽지 않았다. 도대체 어디에 조형물이 있는 것인가? 무한 클릭을 시도하다가 끝내 플래그에 맞는 좌표값을 찾았다.

![image](https://user-images.githubusercontent.com/44149738/131461551-351ccfd7-cf87-4ee5-8dc4-93eeb778ca75.png)

## flag
```
wormcon{41.878_12.481}
```