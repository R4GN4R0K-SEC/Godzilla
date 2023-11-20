# GODZILLA
![raw](https://repository-images.githubusercontent.com/721252319/1071e58c-f9a7-4844-82d0-66bcb45aefb4)
Godzilla does not have any commercial version/payload version.

## Runtime environment
 1. JavaDynamicPayload -> java1.0及以上
 2. CShapDynamicPayload -> .net2.0及以上
 3. PhpDynamicPayload ->  4.3.0及以上
 4. AspDynamicPayload -> 全版本

## Introduction of Godzilla


### Payload and encryptor support

Godzilla has 3 built-in Payloads, 6 built-in encryptors, 6 built-in script suffixes, and 20 built-in plug-ins

 1. JavaDynamicPayload
	 1. JAVA_AES_BASE64
	 	1. jsp
	 	2. jspx
     2. JAVA_AES_RAW
	     1. jsp
	     2. jspx

 2. CShapDynamicPayload
	 1. CSHAP_AES_BASE64
		 1. aspx
		 2. asmx
		 3. ashx
	 2. JAVA_AES_RAW
		 1. aspx
		 2. asmx
		 3. ashx
 3. PhpDynamicPayload
	 1. PHP_XOR_BASE64
		 1. php
     2. PHP_XOR_RAW
	     1. php

### Raw or Base64 encryptor features

Raw : Raw is to send or output encrypted data directly

![raw](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/raw.png)

Base64 : Base64 encoding of the encrypted data

![base64](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/base64.png)

## Plug-in support

 1. JavaDynamicPayload
       1. MemoryShell

     ```
    Support Godzilla, Ice Scorpion, Chopper, ReGeorg's memory shell and uninstallation support
     ```

       2. Screen

     ```
     屏幕截图
     ```

       3. JRealCmd

     ```
     虚拟终端 可以用netcat连接
     ```

       4. JMeterpreter

     ```
     与MSF联动
     ```

       5. ServletManage

     ```
     Servlet管理 Servlet卸载
     ```

       6. JarLoader

     ```
     内存加载Jar 将Jar加载到 SystemClassLoader
     ```

       7. JZip

     ```
     ZIP压缩 ZIP解压
     ```
 2. CShapDynamicPayload
	 1. CZip
	 ```
	 ZIP压缩 ZIP解压

      ```

     2. ShellcodeLoader

     ```
     Shellcode加载 与MSF联动
     ```

     3. SafetyKatz

     ```
     Mimikatz
     ```

     4. lemon

     ```
     读取服务器 FileZilla navicat sqlyog Winscp xmangager 的配置信息以及密码
     ```

     5. CRevlCmd

     ```
     虚拟终端 可以用netcat连接
     ```

     6. BadPotato

     ```
     Windows权限提升 2012-2019
     ```

     7. ShapWeb
	 ```
     读取服务器 谷歌 IE 火狐 浏览器保存的账号密码
     ```
     8. SweetPotato

     ```
      Windwos权限提升		烂土豆的C#版本 甜土豆 
     ```
 3. PhpDynamicPayload
     1. PMeterpreter

     ```
     与MSF联动
     ```

     2. ByPassOpenBasedir

     ```
     绕过OpenBasedir
     ```

     3. PZip

     ```
     ZIP压缩 ZIP解压
     ```

     4. P_Eval_Code

     ```
     代码执行
     ```

     5. BypassDisableFunctions

     ```
     绕过 DisableFunctions
     ```

     [![Stargazers over time](https://starchart.cc/BeichenDream/Godzilla.svg)](https://starchart.cc/BeichenDream/Godzilla)
