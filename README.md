![KnowSecTeam](https://github.com/R4GN4R0K-SEC/Godzilla/assets/74421852/3703ddfd-01c5-44f9-bdbd-7df20c49f2a3)
# GODZILLA
![BeichenDream GODZILLA coder](https://github.com/R4GN4R0K-SEC/Godzilla/assets/74421852/0a8ffb2c-b835-4c31-beba-6df387f55a2d)
> # ***Godzilla has 3 built-in Payloads, 6 built-in encryptors, 6 built-in script suffixes, and 20 built-in plug-ins***
> ***Godzilla does not have any commercial version/payload version***

# Runtime environment
 1. JavaDynamicPayload -> java1.0及以上
 2. CShapDynamicPayload -> .net2.0及以上
 3. PhpDynamicPayload ->  4.3.0及以上
 4. AspDynamicPayload -> 全版本

<h3><center>"Nation-State Cyberattacks"</center></h3>

<h4><i>Targeted Attack Campaign Against ManageEngine ADSelfService Plus Delivers Godzilla Webshells, NGLite Trojan and KdcSponge Stealer</i></h4>

<p>On Sept. 16, 2021, the US Cybersecurity and Infrastructure Security Agency (CISA) released an <a href="https://us-cert.cisa.gov/ncas/alerts/aa21-259a">alert</a> warning that advanced persistent threat (APT) actors were actively exploiting newly identified vulnerabilities in a self-service password management and single sign-on solution known as ManageEngine ADSelfService Plus. The alert explained that malicious actors were observed deploying a specific webshell and other techniques to maintain persistence in victim environments; however, in the days that followed, we observed a second unrelated campaign carry out successful attacks against the same vulnerability.</p>
<p>As early as Sept. 17 the actor leveraged leased infrastructure in the United States to scan hundreds of vulnerable organizations across the internet. Subsequently, exploitation attempts began on Sept. 22 and likely continued into early October. During that window, the actor successfully compromised at least nine global entities across the technology, defense, healthcare, energy and education industries.</p>
<p>Following initial exploitation, a payload was uploaded to the victim network which installed a <a href="https://github.com/BeichenDream/Godzilla/">Godzilla</a> webshell. This activity was consistent across all victims; however, we also observed a smaller subset of compromised organizations who subsequently received a modified version of a new backdoor called <a href="https://github.com/Maka8ka/NGLite">NGLite</a>. The threat actors then used either the webshell or the NGLite payload to run commands and move laterally to other systems on the network, while they exfiltrated files of interest simply by downloading them from the web server. Once the actors pivoted to a domain controller, they installed a new credential-stealing tool that we track as KdcSponge.</p>
<p>Both Godzilla and NGLite were developed with Chinese instructions and are publicly available for download on GitHub. We believe threat actors deployed these tools in combination as a form of redundancy to maintain access to high-interest networks. Godzilla is a functionality-rich webshell that parses inbound HTTP POST requests, decrypts the data with a secret key, executes decrypted content to carry out additional functionality and returns the result via a HTTP response. This allows attackers to keep code likely to be flagged as malicious off the target system until they are ready to dynamically execute it.</p>
<p>NGLite is characterized by its author as an “anonymous cross-platform remote control program based on blockchain technology.” It leverages <a href="https://nkn.org/">New Kind of Network (NKN)</a> infrastructure for its command and control (C2) communications, which theoretically results in anonymity for its users. It's important to note that NKN is a legitimate networking service that uses blockchain technology to support a decentralized network of peers. The use of NKN as a C2 channel is very uncommon. We have seen only 13 samples communicating with NKN altogether – nine NGLite samples and four related to a legitimate open-source utility called <a href="https://github.com/rule110-io/surge">Surge</a> that uses NKN for file sharing.</p>
<p>Finally, KdcSponge is a novel credential-stealing tool that is deployed against domain controllers to steal credentials. KdcSponge injects itself into the Local Security Authority Subsystem Service (LSASS) process and will hook specific functions to gather usernames and passwords from accounts attempting to authenticate to the domain via Kerberos. The malicious code writes stolen credentials to a file but is reliant on other capabilities for exfiltration.</p>
<p>Palo Alto Networks customers are protected against this campaign through the following:</p>
<ul>
<li><a href="https://www.paloaltonetworks.com/cortex/cortex-xdr">Cortex XDR</a> local analysis blocks the NGLite backdoor.</li>
<li>All known samples (Dropper, NGLite, KdcSponge) are classified as malware in <a href="https://www.paloaltonetworks.com/products/secure-the-network/wildfire">WildFire</a>.</li>
<li><a href="https://www.paloaltonetworks.com/cortex/cortex-xpanse">Cortex Xpanse</a> can accurately identify Zoho ManageEngine ADSelfServicePlus, ManageEngine Desktop Central or ManageEngine ServiceDeskPlus Servers across customer networks.</li>
</ul>

****************************************
## Introduction
### Payload and encryptor support
Godzilla has 3 built-in payloads and 6 encryptors, 6 supported script suffixes, and 20 built-in plug-ins

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

### Raw or Base64 Encryptor Difference

Raw: Raw is to send or output the encrypted data directly

![raw](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/raw.png)

Base64: Base64 is to encode the encrypted data again

![base64](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/base64.png)

## Plugin Support

1. JavaDynamicPayload
1. MemoryShell

```
Supports the memory shell of Godzilla, Ice Scorpion, Cleaver, ReGeorg and supports uninstallation
```

2. Screen

```
Screenshot
```

3. JRealCmd

```
Virtual terminal can be connected with netcat
```

4. JMeterpreter

```
Linked with MSF
```

5. ServletManage

```
Servlet management Servlet uninstallation
```

6. JarLoader

```
Memory loading Jar Load Jar into SystemClassLoader
```

7. JZip

```
ZIP compression ZIP decompression
```
2. CShapDynamicPayload
1. CZip
```
ZIP compression ZIP decompression

```

2. ShellcodeLoader

```
Shellcode loading Linked with MSF
```

3. SafetyKatz

```
Mimikatz
```

4. lemon

```
Read server FileZilla navicat sqlyog Winscp xmangager configuration information and password
```

5. CRevlCmd

```
Virtual terminal can be connected with netcat
```

6. BadPotato

```
Windows privilege escalation 2012-2019
```

7. ShapWeb
```
Read the account password saved by the server Google IE Firefox browser
```
8. SweetPotato

```
Windwos privilege escalation C# version of rotten potato Sweet potato
```
3. PhpDynamicPayload
1. PMeterpreter

```
Linked with MSF
```

2. ByPassOpenBasedir

```
Bypass OpenBasedir
```
3. PZip

```
ZIP compression ZIP decompression
```

4. P_Eval_Code

```
Code Execution
```

5. BypassDisableFunctions

```
Bypass DisableFunctions
```

 [![Stargazers over time](https://starchart.cc/BeichenDream/Godzilla.svg)](https://starchart.cc/BeichenDream/Godzilla)



# INTRODUCTION 
### Payload and Encryptor Support
Godzilla has 3 built-in Payloads and 6 built-in Encryptors, 6 supported script suffixes, and 20 built-in plugins
简介
Payload以及加密器支持
哥斯拉内置了3种Payload以及6种加密器,6种支持脚本后缀,20个内置插件
### Payload以及加密器支持

哥斯拉内置了3种Payload以及6种加密器,6种支持脚本后缀,20个内置插件

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

### Raw or Base64 加密器区别

Raw : Raw是将加密后的数据直接发送或者输出

![raw](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/raw.png)

Base64 : Base64是将加密后的数据再进行Base64编码

![base64](https://raw.githubusercontent.com/BeichenDream/Godzilla/master/base64.png)

## 插件支持

 1. JavaDynamicPayload
       1. MemoryShell

     ```
     支持 哥斯拉 冰蝎 菜刀 ReGeorg 的内存shell  并且支持卸载
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








<h2><a id="post-120911-_21umtld5lxs3"></a>Initial Access</h2>
<p>Beginning on Sept. 17 and continuing through early October, we observed scanning against ManageEngine ADSelfService Plus servers. Through global telemetry, we believe that the actor targeted at least 370 Zoho ManageEngine servers in the United States alone. Given the scale, we assess that these scans were largely indiscriminate in nature as targets ranged from education to Department of Defense entities.</p>
<p>Upon obtaining scan results, the threat actor transitioned to exploitation attempts on Sept. 22. These attempts focused on <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40539">CVE-2021-40539</a>, which allows for REST API authentication bypass with resultant remote code execution in vulnerable devices. To achieve this result, the actors delivered uniquely crafted POST statements to the REST API LicenseMgr.</p>
<p>While we lack insight into the totality of organizations that were exploited during this campaign, we believe that, globally, at least nine entities across the technology, defense, healthcare, energy and education industries were compromised. Following successful exploitation, the actor uploaded a payload which deployed a Godzilla webshell, thereby enabling additional access to a victim network. The following leased IP addresses in the United States were observed interacting with compromised servers:</p>
<p><span style="font-family: 'courier new', courier, monospace;">24.64.36[.]238</span><br />
<span style="font-family: 'courier new', courier, monospace;">45.63.62[.]109</span><br />
<span style="font-family: 'courier new', courier, monospace;">45.76.173[.]103</span><br />
<span style="font-family: 'courier new', courier, monospace;">45.77.121[.]232</span><br />
<span style="font-family: 'courier new', courier, monospace;">66.42.98[.]156</span><br />
<span style="font-family: 'courier new', courier, monospace;">140.82.17[.]161</span><br />
<span style="font-family: 'courier new', courier, monospace;">149.28.93[.]184</span><br />
<span style="font-family: 'courier new', courier, monospace;">149.248.11[.]205 </span><br />
<span style="font-family: 'courier new', courier, monospace;">199.188.59[.]192</span></p>
<p>Following the deployment of the webshell, which appears consistent across all victims, we also identified the use of additional tools deployed in a subset of compromised networks. Specifically, the actors deployed a custom variant of an open-source backdoor called NGLite and a credential-harvesting tool we track as KdcSponge. The following sections provide detailed analysis of these tools.</p>
<h2><a id="post-120911-_f4zstnqwec6"></a>Malware</h2>
<p>At the time of exploitation, two different executables were saved to the compromised server: <span style="font-family: 'courier new', courier, monospace;">ME_ADManager.exe</span> and <span style="font-family: 'courier new', courier, monospace;">ME_ADAudit.exe</span>. The <span style="font-family: 'courier new', courier, monospace;">ME_ADManager.exe</span> file acts as a dropper Trojan that not only saves a Godzilla webshell to the system, but also installs and runs the other executable saved to the system, specifically <span style="font-family: 'courier new', courier, monospace;">ME_ADAudit.exe</span>. The <span style="font-family: 'courier new', courier, monospace;">ME_ADAudit.exe</span> executable is based on NGLite, which the threat actors use as their payload to run commands on the system.</p>
<h3><a id="post-120911-_whfs1f1uvfif"></a><span style="font-family: 'courier new', courier, monospace;">ME_ADManager.exe</span> Dropper</h3>
<p>After initial exploitation, the dropper is saved to the following path:</p>
<p><span style="font-family: 'courier new', courier, monospace;">c:\Users\[username]\AppData\Roaming\ADManager\ME_ADManager.exe</span></p>
<p>Analysis of this file revealed that the author of this payload did not remove debug symbols when building the sample. Thus, the following debug path exists within the sample and suggests the username pwn was used to create this payload:</p>
<p><span style="font-family: 'courier new', courier, monospace;">c:\Users\pwn\documents\visual studio 2015\Projects\payloaddll\Release\cmd.pdb</span></p>
<p>Upon execution, the sample starts off by creating the following generic mutex found in many code examples freely available on the internet, which is meant to avoid running more than one instance of the dropper:</p>
<p><span style="font-family: 'courier new', courier, monospace;">cplusplus_me</span></p>
<p>The dropper then attempts to write a hardcoded Godzilla webshell, which we will provide a detailed analysis of later in this report, to the following locations:</p>
<p><span style="font-family: 'courier new', courier, monospace;">../webapps/adssp/help/admin-guide/reports.jsp<br />
</span><span style="font-family: 'courier new', courier, monospace;">c:/ManageEngine/ADSelfService Plus/webapps/adssp/help/admin-guide/reports.jsp<br />
</span><span style="font-family: 'courier new', courier, monospace;">../webapps/adssp/selfservice/assets/fonts/lato/lato-regular.jsp<br />
</span><span style="font-family: 'courier new', courier, monospace;">c:/ManageEngine/ADSelfService Plus/webapps/adssp/selfservice/assets/fonts/lato/lato-regular.jsp</span></p>
<p>The dropper then creates the folder <span style="font-family: 'courier new', courier, monospace;">%APPDATA%\ADManager</span> and copies itself to <span style="font-family: 'courier new', courier, monospace;">%APPDATA%\ADManager\ME_ADManager.exe</span> before creating the following registry keys to persistently run after reboot:</p>
<p><span style="font-family: 'courier new', courier, monospace;">Software\Microsoft\Windows\CurrentVersion\Run\ME_ADManager.exe : %APPDATA%\ADManager\ME_ADManager.exe<br />
</span><span style="font-family: 'courier new', courier, monospace;">Software\Microsoft\Windows\CurrentVersion\Run\ME_ADAudit.exe : %SYSTEM32%\ME_ADAudit.exe<br />
</span><span style="font-family: 'courier new', courier, monospace;">The dropper then copies ADAudit.exe from the current directory to the following path and runs the file with WinExec:<br />
</span><span style="font-family: 'courier new', courier, monospace;">%SYSTEM32%\ME_ADAudit.exe</span></p>
<p>The dropper does not write the <span style="font-family: 'courier new', courier, monospace;">ME_ADAudit.exe</span> file to disk, meaning the threat actor must upload this file to the server prior to the execution of the dropper, likely as part of the initial exploitation of the <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40539">CVE-2021-40539</a> vulnerability. During our analysis of multiple incidents, we found that the ME_ADAudit.exe sample maintained a consistent SHA256 hash of <span style="font-family: 'courier new', courier, monospace;">805b92787ca7833eef5e61e2df1310e4b6544955e812e60b5f834f904623fd9f</span>, therefore suggesting that the actor deployed the same customized version of the NGLite backdoor against multiple targets.</p>
<h2><a id="post-120911-_37m09dl6ut5z"></a>Godzilla Webshell</h2>
<p>As mentioned previously, the initial dropper contains a Java Server Page (JSP) webshell hardcoded within it. Upon analysis of the webshell, it was determined to be the Chinese-language <a href="https://github.com/BeichenDream/Godzilla/">Godzilla</a> webshell V3.00+. The Godzilla webshell was developed by user BeichenDream, who stated they created this webshell because the ones available at the time would frequently be detected by security products during red team engagements. As such, the author advertises it will avoid detection by leveraging AES encryption for its network traffic and that it maintains a very low static detection rate across security vendor products.</p>
<figure id="attachment_120914" aria-describedby="caption-attachment-120914" style="width: 390px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120914" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image.png" alt="The chart shows detections on VirusTotal for Godzilla webshells. Columns read detections, size, first seen and last seen. " width="390" height="415" /><figcaption id="caption-attachment-120914" class="wp-caption-text">Figure 1. Detections on VirusTotal for Godzilla webshells.</figcaption></figure>
<p>It’s no surprise that the Godzilla webshell has been adopted by regional threat groups during their intrusions, as it offers more functionality and network evasion than other webshells used by the same groups, such as <a href="https://unit42.paloaltonetworks.com/tag/china-chopper/">ChinaChopper</a>.</p>
<p>The JSP webshell itself is fairly straightforward in terms of functionality and maintains a lightweight footprint. Its primary function is to parse an HTTP POST, decrypt the content with the secret key and then execute the payload. This allows attackers to keep code likely to be flagged as malicious off the target system until they are ready to dynamically execute it.</p>
<p>The below image shows the initial part of the default JSP webshell as well as the decrypt function.</p>
<figure id="attachment_120916" aria-describedby="caption-attachment-120916" style="width: 652px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120916" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-1.png" alt="The initial part of the default JSP webshell as well as the decrypt function. Of note are the variables xc and pass in the first and second lines of the code. " width="652" height="366" /><figcaption id="caption-attachment-120916" class="wp-caption-text">Figure 2. Header of a default Godzilla JSP webshell.</figcaption></figure>
<p>Of note are the variables <span style="font-family: 'courier new', courier, monospace;">xc</span> and <span style="font-family: 'courier new', courier, monospace;">pass</span> in the first and second lines of the code shown in Figure 2. These are the main components that change each time an operator generates a new webshell, and the variables represent the secret key used for AES decryption within that webshell.</p>
<p>When you generate the webshell manually, you specify a plaintext pass and key. By default, these are <span style="font-family: 'courier new', courier, monospace;">pass</span> and <span style="font-family: 'courier new', courier, monospace;">key</span>.</p>
<figure id="attachment_120918" aria-describedby="caption-attachment-120918" style="width: 487px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120918" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-2.png" alt="The screenshot shows the Chinese-language Godzilla interface, with default webshell values of pass and key. " width="487" height="330" /><figcaption id="caption-attachment-120918" class="wp-caption-text">Figure 3. Godzilla default webshell values.</figcaption></figure>
<p>To figure out how these are presented in the webshell itself, we can take a look at the Godzilla JAR file.</p>
<p>Below, you can see the code substitutes the strings in one of the embedded webshell templates under the <span style="font-family: 'courier new', courier, monospace;">/shells/cryptions/JavaAES/GenerateShellLoder</span> function.</p>
<figure id="attachment_120920" aria-describedby="caption-attachment-120920" style="width: 666px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120920" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-3.png" alt="The code shown substitutes the strings in one of the embedded webshell templates under the /shells/cryptions/JavaAES/GenerateShellLoder function. " width="666" height="157" /><figcaption id="caption-attachment-120920" class="wp-caption-text">Figure 4. GenerateShellLoder function in Generate.class file.</figcaption></figure>
<p>Thus we know the xc variable in the webshell will be the AES secret key, as indicated in the template.</p>
<p><span style="font-family: 'courier new', courier, monospace;">String xc="{secretKey}"; String pass="{pass}"; String md5=md5(pass+xc)</span>;</p>
<p>We observed that the xc value appears to be a hash, and under the <span style="font-family: 'courier new', courier, monospace;">/core/shell/ShellEntity.class</span> file, we can see the code takes the first 16 characters of the MD5 hash for a plaintext secret key.</p>
<p style="padding-left: 40px;"><span style="font-family: 'courier new', courier, monospace;">public String getSecretKeyX()<br />
</span><span style="font-family: 'courier new', courier, monospace;">{</span></p>
<p style="padding-left: 80px;"><span style="font-family: 'courier new', courier, monospace;">return functions.md5(getSecretKey()).substring(0, 16);</span></p>
<p style="padding-left: 40px;"><span style="font-family: 'courier new', courier, monospace;">}</span></p>
<p>With that, we know then that the <span style="font-family: 'courier new', courier, monospace;">xc</span> value of <span style="font-family: 'courier new', courier, monospace;">3c6e0b8a9c15224a</span> is the first 16 characters of the MD5 hash for the word <span style="font-family: 'courier new', courier, monospace;">key</span>.</p>
<p>Given this, the <span style="font-family: 'courier new', courier, monospace;">xc</span> and <span style="font-family: 'courier new', courier, monospace;">pass</span> variables are the two primary fields that can be used for tracking and attempting to map activity across incidents. For the purpose of this blog, we generated a Godzilla webshell with the default options for analysis; however, the only differences between the default one and the ones observed in attacks are different <span style="font-family: 'courier new', courier, monospace;">xc</span> and <span style="font-family: 'courier new', courier, monospace;">pass</span> values.</p>
<p>One important characteristic of this webshell is that the author touts the lack of static detection and has tried to make this file not stand out through avoiding keywords or common structures that might be recognized by security product signatures. One particularly interesting static evasion technique is the use of a Java ternary conditional operator to indicate decryption.</p>
<p>The conditional here is <span style="font-family: 'courier new', courier, monospace;">m?1:2 – m</span> is a boolean value passed to this function, as shown previously in Figure 2. If m is True, then the first expression constant (<span style="font-family: 'courier new', courier, monospace;">1</span>) is used. Otherwise, the second (<span style="font-family: 'courier new', courier, monospace;">2</span>) is passed. Referring to the Java documentation, <span style="font-family: 'courier new', courier, monospace;">1</span> is <span style="font-family: 'courier new', courier, monospace;">ENCRYPT_MODE</span>, whereas <span style="font-family: 'courier new', courier, monospace;">2</span> is <span style="font-family: 'courier new', courier, monospace;">DECRYPT_MODE</span>.</p>
<figure id="attachment_120922" aria-describedby="caption-attachment-120922" style="width: 900px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120922" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-4.png" alt="Java documentation showing the meaning of crypto constants. 1 is ENCRYPT_MODE and 2 is DECRYPT_MODE." width="900" height="94" /><figcaption id="caption-attachment-120922" class="wp-caption-text">Figure 5. JavaX crypto constants meaning.</figcaption></figure>
<p>When the webshell executes this function <span style="font-family: 'courier new', courier, monospace;">x</span>, it does not set the value of <span style="font-family: 'courier new', courier, monospace;">m</span>, thus forcing <span style="font-family: 'courier new', courier, monospace;">m</span> to <span style="font-family: 'courier new', courier, monospace;">False</span> and setting it to decrypt.</p>
<p><span style="font-family: 'courier new', courier, monospace;">response.getWriter().write(base64Encode(x(base64Decode(f.toString()), true)));</span></p>
<p>To understand the capabilities of Godzilla then, we can take a look in <span style="font-family: 'courier new', courier, monospace;">/shells/payloads/java/JavaShell.class</span>. This class file contains all of the functions provided to the operator. Below is an example of the <span style="font-family: 'courier new', courier, monospace;">getFile</span> function.</p>
<figure id="attachment_120924" aria-describedby="caption-attachment-120924" style="width: 661px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120924" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-5.png" alt="To understand the capabilities of Godzilla then, we can take a look in /shells/payloads/java/JavaShell.class. This class file contains all of the functions provided to the operator. Shown is an example of the getFile function." width="661" height="116" /><figcaption id="caption-attachment-120924" class="wp-caption-text">Figure 6. getFile function payload for Godzilla.</figcaption></figure>
<p>Payload functions:</p>
<p><span style="font-family: 'courier new', courier, monospace;">getFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">downloadFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">getBasicsInfo<br />
</span><span style="font-family: 'courier new', courier, monospace;">uploadFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">copyFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">deleteFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">newFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">newDir<br />
</span><span style="font-family: 'courier new', courier, monospace;">currentDir<br />
</span><span style="font-family: 'courier new', courier, monospace;">currentUserName<br />
</span><span style="font-family: 'courier new', courier, monospace;">bigFileUpload<br />
</span><span style="font-family: 'courier new', courier, monospace;">bigFileDownload<br />
</span><span style="font-family: 'courier new', courier, monospace;">getFileSize<br />
</span><span style="font-family: 'courier new', courier, monospace;">execCommand<br />
</span><span style="font-family: 'courier new', courier, monospace;">getOsInfo<br />
</span><span style="font-family: 'courier new', courier, monospace;">moveFile<br />
</span><span style="font-family: 'courier new', courier, monospace;">getPayload<br />
</span><span style="font-family: 'courier new', courier, monospace;">fileRemoteDown<br />
</span><span style="font-family: 'courier new', courier, monospace;">setFileAttr</span></p>
<p>As evidenced by the names of the functions, the Godzilla webshell offers numerous payloads for navigating remote systems, transferring data to and from, remote command execution and enumeration.</p>
<p>These payloads will be encrypted with the secret key previously described, and the operating software will send an HTTP POST to the compromised system containing the data.</p>
<p>Additionally, if we examine the <span style="font-family: 'courier new', courier, monospace;">core/ui/component/dialog/ShellSetting.class</span> file (shown below), the <span style="font-family: 'courier new', courier, monospace;">initAddShellValue</span>() function contains the default configuration settings for remote network access. Therefore, elements such as static HTTP headers and User-Agent strings can be identified in order to aid forensic efforts searching web access logs for potential compromise.</p>
<p style="padding-left: 40px;"><span style="font-family: 'courier new', courier, monospace;">private void initAddShellValue() {</span></p>
<p style="padding-left: 80px;"><span style="font-family: 'courier new', courier, monospace;">this.shellContext = new ShellEntity();</span></p>
<p style="padding-left: 80px;"><span style="font-family: 'courier new', courier, monospace;">this.urlTextField.setText("http://127.0.0.1/shell.jsp");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.passwordTextField.setText("pass");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.secretKeyTextField.setText("key");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.proxyHostTextField.setText("127.0.0.1");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.proxyPortTextField.setText("8888");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.connTimeOutTextField.setText("60000");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.readTimeOutTextField.setText("60000");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.remarkTextField.setText("??");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.headersTextArea.setText("User-Agent: Mozilla/5.0 (Windows NT<br />
10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\nAccept-Language:<br />
</span><span style="font-family: 'courier new', courier, monospace;"> zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\n");</span></p>
<p style="padding-left: 80px;"><span style="font-family: 'courier new', courier, monospace;">this.leftTextArea.setText("");<br />
</span><span style="font-family: 'courier new', courier, monospace;">this.rightTextArea.setText("");</span></p>
<p style="padding-left: 40px;"><span style="font-family: 'courier new', courier, monospace;">}</span></p>
<p>To illustrate, below is a snippet of the web server access logs that show the initial exploit using the Curl application and sending the custom URL payload to trigger the CVE-2021-40539 vulnerability. It then shows the subsequent access of the Godzilla webshell, which has been placed into the hardcoded paths by the initial dropper. By reviewing the User-Agent, we can determine that the time from exploit to initial webshell access took just over four minutes for the threat actor.</p>
<p><span style="font-family: 'courier new', courier, monospace;">- /./RestAPI/LicenseMgr "-" X.X.X.X Y.Y.Y.Y POST [00:00:00] - - 200 "curl/7.68.0"<br />
</span><span style="font-family: 'courier new', courier, monospace;">- /help/admin-guide/reports.jsp "-" X.X.X.X Y.Y.Y.Y POST [+00:04:07] - - 200 "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0"</span></p>
<h2><a id="post-120911-_y8ka58ljvmkx"></a>Custom NGLite</h2>
<p>NGLite is an open-source backdoor written in the Go language (specifically Go version 1.13). It is available for download from a public <a href="https://github.com/Maka8ka/NGLite">GitHub repository</a>. NGLite is a backdoor Trojan that is only capable of running commands received through its C2 channel. While the capabilities are standard for a backdoor, NGLite uses a novel C2 channel that leverages a decentralized network based on the legitimate NKN to communicate between the backdoor and the actors.</p>
<p>The NKN touts that their decentralized network uses a public blockchain and can support communication between millions of peers, each of which are identified by a unique NKN address instead of the typical network identifiers, such as IP addresses. Therefore, the immediate IP address that the NGLite tool communicates with in its C2 channel is just a peer in the decentralized network and is unlikely to represent the threat actor’s network location. This design makes detection and prevention of the NGLite C2 communication channel difficult.</p>
<p>Fortunately, the use of NKN as a C2 channel is very uncommon. We have seen only 13 samples communicating with NKN altogether – nine NGLite samples and four related to an open-source utility called <a href="https://github.com/rule110-io/surge">Surge</a> that uses NKN for file sharing. Eight of the nine known NGLite samples were scanned by VirusTotal. Four were undetected, three were detected by one antivirus and the remaining sample was detected by five. This low detection rate suggests that NGLite had very little antivirus coverage during this attack campaign.</p>
<p>As mentioned in the previous section, the dropper creates registry keys and executes a custom variant of the NGLite backdoor (SHA256: <span style="font-family: 'courier new', courier, monospace;">805b92787ca7833eef5e61e2df1310e4b6544955e812e60b5f834f904623fd9f</span>) saved at the following path:</p>
<p><span style="font-family: 'courier new', courier, monospace;">C:\Windows\system32\ME_ADAudit.exe</span></p>
<p>The data structures within the Go-based backdoor contain the following path, which is used to store the main source code for this custom variant of NGLite on the developers’ system:</p>
<p><span style="font-family: 'courier new', courier, monospace;">/mnt/hgfs/CrossC2-2.2/src/ng.com/lprey/main.go</span></p>
<p>Based on this path, one might surmise that the actor used <a href="https://github.com/gloxec/CrossC2/tree/v2.2/src">CrossC2</a> to build a cross platform Cobalt Strike C2 payload; however, we have no reason to believe that this payload is actually based on CrossC2, as the payload is a customized version of the publicly available NGLite backdoor.</p>
<p>It is possible that the threat actors included the CrossC2 string in the path as a misdirection, hoping to confuse threat analysts into thinking they are delivering a Cobalt Strike payload. We have seen the following NGLite samples using this same source code path dating back to Aug. 11, which suggests that this threat actor has been using this tool for several months:</p>
<p><span style="font-family: 'courier new', courier, monospace;">3da8d1bfb8192f43cf5d9247035aa4445381d2d26bed981662e3db34824c71fd<br />
</span><span style="font-family: 'courier new', courier, monospace;">5b8c307c424e777972c0fa1322844d4d04e9eb200fe9532644888c4b6386d755<br />
</span><span style="font-family: 'courier new', courier, monospace;">3f868ac52916ebb6f6186ac20b20903f63bc8e9c460e2418f2b032a207d8f21d</span></p>
<p>The custom NGLite sample used in this campaign checks the command line arguments for g or group value. If this switch is not present, the payload will use the default string <span style="font-family: 'courier new', courier, monospace;">7aa7ad1bfa9da581a7a04489896279517eef9357b81e406e3aee1a66101fe824</span> in what NGLite refers to as its seed identifier.</p>
<p>The payload will create what it refers to as a <span style="font-family: 'courier new', courier, monospace;">prey id</span>, which is generated by concatenating the MAC address of the system network interface card (NIC) and IPv4 address, with a hyphen (-) separating the two. This prey identifier will be used in the C2 communications.</p>
<p>The NGLite payload will use the NKN decentralized network for C2 communications. See the NKN client configuration in the sample below:</p>
<figure id="attachment_120926" aria-describedby="caption-attachment-120926" style="width: 900px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120926" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-6.png" alt="The NGLite payload will use the NKN decentralized network for C2 communications. See the NKN client configuration in the sample shown here. " width="900" height="522" /><figcaption id="caption-attachment-120926" class="wp-caption-text">Figure 7. Embedded NKN client configuration.</figcaption></figure>
<p>The sample first starts by reaching out to <span style="font-family: 'courier new', courier, monospace;">seed.nkn[.]org</span> over TCP/30003, specifically with an HTTP POST request that is structured as follows:</p>
<p><figure id="attachment_120928" aria-describedby="caption-attachment-120928" style="width: 900px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120928" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-7.png" alt="The sample first starts by reaching out to seed.nkn[.]org over TCP/30003, specifically with an HTTP POST request that is structured as shown. " width="900" height="185" /><figcaption id="caption-attachment-120928" class="wp-caption-text">Figure 8. Initial NKN HTTP POST.</figcaption></figure>It also will send HTTP POST requests with <span style="font-family: 'courier new', courier, monospace;">monitor_03</span> as the prey id, as seen in the following:</p>
<figure id="attachment_120930" aria-describedby="caption-attachment-120930" style="width: 900px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120930" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-8.png" alt="It also will send HTTP POST requests with monitor_03 as the prey id, as seen here." width="900" height="164" /><figcaption id="caption-attachment-120930" class="wp-caption-text">Figure 9. HTTP Post containing “prey id.”</figcaption></figure>
<p>The <span style="font-family: 'courier new', courier, monospace;">seed.nkn[.]org</span> server responds to this request with the <span style="font-family: 'courier new', courier, monospace;">[prey id (MAC-IPv4)]</span> within the JSON structured as follows:</p>
<p><span style="font-family: 'courier new', courier, monospace;">{"id":"nkn-sdk-go","jsonrpc":"2.0","result":{"addr":"66.115.12.89:30002","id":"223b4f7f4588af02badaa6a83e402b33dea0ba8908e4cd6008f84c2b98a6a7de","pubkey":"38ce48a2a3cffded7c2031514acaef29851ee39303795e4b3e7fce5a6619e6be","rpcAddr":"66.115.12.89:30003"}}</span></p>
<p>This suggests the payload will communicate with the peer at <span style="font-family: 'courier new', courier, monospace;">66.115.12.89</span> over TCP/30003. The <span style="font-family: 'courier new', courier, monospace;">seed.nkn[.]org</span> server then responds to the <span style="font-family: 'courier new', courier, monospace;">monitor_03</span> request with the following, which suggests the payload will communicate with <span style="font-family: 'courier new', courier, monospace;">54.204.73.156</span> over TCP/30003:</p>
<p><span style="font-family: 'courier new', courier, monospace;">{"id":"nkn-sdk-go","jsonrpc":"2.0","result":{"addr":"54.204.73.156:30002","id":"517cb8112456e5d378b0de076e85e80afee3c483d18c30187730d15f18392ef9","pubkey":"99bb5d3b9b609a31c75fdeede38563b997136f30cb06933c9b43ab3f719369aa","rpcAddr":"54.204.73.156:30003"}}</span></p>
<p>After obtaining the response from <span style="font-family: 'courier new', courier, monospace;">seed.nkn[.]org</span>, the payload will issue an HTTP GET request to the IP address and TCP port provided in the <span style="font-family: 'courier new', courier, monospace;">addr</span> field within the JSON. These HTTP requests will appear as follows, but keep in mind that these systems are not actor-controlled; rather, they are just the first peer in a chain of peers that will eventually return the actor’s content:</p>
<p><figure id="attachment_120932" aria-describedby="caption-attachment-120932" style="width: 900px" class="wp-caption aligncenter"><img decoding="async" class="wp-image-120932" src="https://unit42.paloaltonetworks.com/wp-content/uploads/2021/11/word-image-9.png" alt="After obtaining the response from seed.nkn[.]org, the payload will issue an HTTP GET request to the IP address and TCP port provided in the addr field within the JSON. These HTTP requests will appear as shown, but keep in mind that these systems are not actor-controlled; rather, they are just the first peer in a chain of peers that will eventually return the actor’s content." width="900" height="226" /><figcaption id="caption-attachment-120932" class="wp-caption-text">Figure 10. NKN peering.</figcaption></figure>Eventually, the network communications between the custom NGLite client and server are encrypted using AES with the following key:</p>
<p><span style="font-family: 'courier new', courier, monospace;">WHATswrongwithUu</span></p>
<p>The custom NGLite sample will start by sending the C2 an initial beacon that contains the result of the whoami command with the string #windows concatenated, as seen in the following:</p>
<p><span style="font-family: 'courier new', courier, monospace;">[username]#windows</span></p>
<p>After sending the initial beacon, the NGLite sample will run a sub-function called <span style="font-family: 'courier new', courier, monospace;">Preylistener</span> that creates a server that listens for inbound requests. The sample will also listen for inbound communications and will attempt to decrypt them using a default AES key of <span style="font-family: 'courier new', courier, monospace;">1234567890987654</span>. It will run the decrypted contents as a command via the Go method os/exec.Command. The results are then encrypted using the same AES key and sent back to the requester.</p>
<h2><a id="post-120911-_351bljzg6bee"></a>Post-exploitation Activity</h2>
<p>Upon compromising a network, the threat actor moved quickly from their initial foothold to gain access to other systems on the target networks by running commands via their NGLite payload and the Godzilla webshell. After gaining access to the initial server, the actors focused their efforts on gathering and exfiltrating sensitive information from local domain controllers, such as the Active Directory database file (<span style="font-family: 'courier new', courier, monospace;">ntds.dit</span>) and the SYSTEM hive from the registry. Shortly after, we observed the threat actors installing the KdcSponge credential stealer, which we will discuss in detail next. Ultimately, the actor was interested in stealing credentials, maintaining access and gathering sensitive files from victim networks for exfiltration.</p>
<h3><a id="post-120911-_h32fsa3j6faw"></a>Credential Harvesting and KdcSponge</h3>
<p>During analysis, Unit 42 found logs that suggest the threat actors used PwDump and the built-in <span style="font-family: 'courier new', courier, monospace;">comsvcs.dll</span> to create a mini dump of the <span style="font-family: 'courier new', courier, monospace;">lsass.exe</span> process for credential theft; however, when the actor wished to steal credentials from a domain controller, they installed their custom tool that we track as KdcSponge.</p>
<p>The purpose of KdcSponge is to hook API functions from within the LSASS process to steal credentials from inbound attempts to authenticate via the Kerberos service (“KDC Service”). KdcSponge will capture the domain name, username and password to a file on the system that the threat actor would then exfiltrate manually through existing access to the server.</p>
<p>We know of two KdcSponge samples, both of which were named <span style="font-family: 'courier new', courier, monospace;">user64.dll</span>. They had the following SHA256 hashes:</p>
<p><span style="font-family: 'courier new', courier, monospace;">3c90df0e02cc9b1cf1a86f9d7e6f777366c5748bd3cf4070b49460b48b4d4090<br />
</span><span style="font-family: 'courier new', courier, monospace;">​​b4162f039172dcb85ca4b85c99dd77beb70743ffd2e6f9e0ba78531945577665</span></p>
<p>To launch the KdcSponge credential stealer, the threat actor will run the following command to load and execute the malicious module:</p>
<p><span style="font-family: 'courier new', courier, monospace;">regsvr32 /s user64.dll</span></p>
<p>Upon first execution, the <span style="font-family: 'courier new', courier, monospace;">regsvr32</span> application runs the <span style="font-family: 'courier new', courier, monospace;">DllRegisterServer</span> function exported by <span style="font-family: 'courier new', courier, monospace;">user64.dll</span>. The <span style="font-family: 'courier new', courier, monospace;">DllRegisterServer</span> function resolves the <span style="font-family: 'courier new', courier, monospace;">SetSfcFileException</span> function within <span style="font-family: 'courier new', courier, monospace;">sfc_os.dll</span> and attempts to disable Windows File Protection (WFP) on the <span style="font-family: 'courier new', courier, monospace;">c:\windows\system32\kdcsvc.dll</span> file. It then attempts to inject itself into the running <span style="font-family: 'courier new', courier, monospace;">lsass.exe</span> process by:</p>
<p>1. Opening the <span style="font-family: 'courier new', courier, monospace;">lsass.exe</span> process using <span style="font-family: 'courier new', courier, monospace;">OpenProcess</span>.<br />
2. Allocating memory in the remote process using <span style="font-family: 'courier new', courier, monospace;">VirtualAllocEx</span>.<br />
3. Writing the string <span style="font-family: 'courier new', courier, monospace;">user64.dll</span> to the allocated memory using <span style="font-family: 'courier new', courier, monospace;">WriteProcessMemory</span>.<br />
4. Calling <span style="font-family: 'courier new', courier, monospace;">LoadLibraryA</span> within the <span style="font-family: 'courier new', courier, monospace;">lsass.exe</span> process with <span style="font-family: 'courier new', courier, monospace;">user64.dll</span> as the argument, using <span style="font-family: 'courier new', courier, monospace;">RtlCreateUserThread</span>.</p>
<p>Now that <span style="font-family: 'courier new', courier, monospace;">user64.dll</span> is running within the <span style="font-family: 'courier new', courier, monospace;">lsass.exe</span> process, it will start by creating the following registry key to establish persistence through system reboots:</p>
<p><span style="font-family: 'courier new', courier, monospace;">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\KDC Service : regsvr32 /s user64.dll</span></p>
<p>From there, the sample will check to make sure the system is running a Kerberos service by attempting to obtain a handle to one of the following modules:</p>
<p><span style="font-family: 'courier new', courier, monospace;">kdcsvc.dll<br />
</span><span style="font-family: 'courier new', courier, monospace;">kdccli.dll<br />
</span><span style="font-family: 'courier new', courier, monospace;">Kdcsvs.dll</span></p>
<p>KdcSponge tries to locate three undocumented API functions – specifically <span style="font-family: 'courier new', courier, monospace;">KdcVerifyEncryptedTimeStamp</span>, <span style="font-family: 'courier new', courier, monospace;">KerbHashPasswordEx3</span> and <span style="font-family: 'courier new', courier, monospace;">KerbFreeKey</span> – using the following three methods:</p>
<ol>
<li>Identifies the version of Kerberos module and uses hardcoded offsets to API functions to hook.</li>
<li>Reaches out to Microsoft’s symbol server to find the offset to API functions within Kerberos module and confirms the correct functions by comparing to hardcoded byte sequences.</li>
<li>Searches the Kerberos module for hardcoded byte sequences.</li>
</ol>
<p>The primary method in which KdcSponge locates the API functions to hook is based on determining the version of the Kerberos module based on the <span style="font-family: 'courier new', courier, monospace;">TimeDateStamp</span> value within the <span style="font-family: 'courier new', courier, monospace;">IMAGE_FILE_HEADER</span> section of the portable executable (PE) file. Once the version of the Kerberos module is determined, KdcSponge has hardcoded offsets that it will use to hook the appropriate functions within that version of the module. KdcSponge looks for the following <span style="font-family: 'courier new', courier, monospace;">TimeDateStamp</span> values:</p>
<p><span style="font-family: 'courier new', courier, monospace;">2005-12-14 01:24:41<br />
</span><span style="font-family: 'courier new', courier, monospace;">2049-10-09 00:46:34<br />
</span><span style="font-family: 'courier new', courier, monospace;">2021-04-08 07:30:26<br />
</span><span style="font-family: 'courier new', courier, monospace;">2021-03-04 04:59:27<br />
</span><span style="font-family: 'courier new', courier, monospace;">2020-03-13 03:20:15<br />
</span><span style="font-family: 'courier new', courier, monospace;">2020-02-19 07:55:57<br />
</span><span style="font-family: 'courier new', courier, monospace;">2019-12-19 04:15:06<br />
</span><span style="font-family: 'courier new', courier, monospace;">2019-07-09 03:15:04<br />
</span><span style="font-family: 'courier new', courier, monospace;">2019-05-31 06:02:30<br />
</span><span style="font-family: 'courier new', courier, monospace;">2018-10-10 07:46:08<br />
</span><span style="font-family: 'courier new', courier, monospace;">2018-02-12 21:47:29<br />
</span><span style="font-family: 'courier new', courier, monospace;">2017-03-04 06:27:32<br />
</span><span style="font-family: 'courier new', courier, monospace;">2016-10-15 03:52:20<br />
</span><span style="font-family: 'courier new', courier, monospace;">2020-11-26 03:04:23<br />
</span><span style="font-family: 'courier new', courier, monospace;">2020-06-05 16:15:22<br />
</span><span style="font-family: 'courier new', courier, monospace;">2017-10-14 07:22:03<br />
</span><span style="font-family: 'courier new', courier, monospace;">2017-03-30 19:53:59<br />
</span><span style="font-family: 'courier new', courier, monospace;">2013-09-04 05:49:27<br />
</span><span style="font-family: 'courier new', courier, monospace;">2012-07-26 00:01:13</span></p>
<p>If KdcSponge was unable to determine the version of the Kerberos module and the domain controller is running Windows Server 2016 or Server 2019 (major version 10), the payload will reach out to Microsoft's symbol server (<span style="font-family: 'courier new', courier, monospace;">msdl.microsoft.com</span>) in an attempt to find the location of several undocumented API functions. The sample will issue an HTTPS GET request to a URL structured as follows, with the GUID portion of the URL being the GUID value from the RSDS structure in the <span style="font-family: 'courier new', courier, monospace;">IMAGE_DEBUG_TYPE_CODEVIEW</span> section of the PE:</p>
<p><span style="font-family: 'courier new', courier, monospace;">/download/symbols/[library name].pdb/[GUID]/[library name].pdb</span></p>
<p>The sample will save the results to a file in the following location, again with the GUID for the filename being the GUID value from the RSDS structure in the <span style="font-family: 'courier new', courier, monospace;">IMAGE_DEBUG_TYPE_CODEVIEW</span> section:</p>
<p><span style="font-family: 'courier new', courier, monospace;">ALLUSERPROFILE\Microsoft\Windows\Caches\[GUID].db:</span></p>
<p>As mentioned above, we believe the reason the code reaches out to the symbol server is to find the locations of three undocumented Kerberos-related functions: <span style="font-family: 'courier new', courier, monospace;">KdcVerifyEncryptedTimeStamp</span>, <span style="font-family: 'courier new', courier, monospace;">KerbHashPasswordEx3</span> and <span style="font-family: 'courier new', courier, monospace;">KerbFreeKey</span>. The sample is primarily looking for these functions in the following libraries:</p>
<p><span style="font-family: 'courier new', courier, monospace;">kdcsvc.KdcVerifyEncryptedTimeStamp<br />
</span><span style="font-family: 'courier new', courier, monospace;">kdcsvc.KerbHashPasswordEx3<br />
</span><span style="font-family: 'courier new', courier, monospace;">kdcpw.KerbHashPasswordEx3<br />
</span><span style="font-family: 'courier new', courier, monospace;">kdcsvc.KerbFreeKey<br />
</span><span style="font-family: 'courier new', courier, monospace;">kdcpw.KerbFreeKey</span></p>
<p>If these functions are found, the sample searches for specific byte sequences, as seen in Table 1, to confirm the functions are correct and to validate they have not been modified.</p>
<table style="width: 100.907%;">
<tbody>
<tr>
<td style="width: 39.4074%;"><b>Function</b></td>
<td style="width: 103.888%;"><b>Hex bytes</b></td>
</tr>
<tr>
<td style="width: 39.4074%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KdcVerifyEncryptedTimeStamp</span></td>
<td style="width: 103.888%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5c 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 f0 48 81 ec 10 01 00 00 48 8b 05 a5</span></td>
</tr>
<tr>
<td style="width: 39.4074%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KerbHashPasswordEx3 </span></td>
<td style="width: 103.888%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 55 41 56 41 57 48 8b ec 48 83 ec 50 48 8b da 48 8b</span></td>
</tr>
<tr>
<td style="width: 39.4074%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcpw.KerbHashPasswordEx3</span></td>
<td style="width: 103.888%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 55 41 56 41 57 48 8b ec 48 83 ec 50 48 8b da 48 8b</span></td>
</tr>
<tr>
<td style="width: 39.4074%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcpw.KerbFreeKey </span></td>
<td style="width: 103.888%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5c 24 08 57 48 83 ec 20 48 8b d9 33 c0 8b 49 10 48 8b 7b 18 f3 aa 48 8b 4b 18 ff 15 72 19</span></td>
</tr>
<tr>
<td style="width: 39.4074%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KerbFreeKey</span></td>
<td style="width: 103.888%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5c 24 08 57 48 83 ec 20 48 8b 79 18 48 8b d9 48 85 ff 0f 85 00 c5 01 00 33 c0 48 89 03 48</span></td>
</tr>
</tbody>
</table>
<p style="text-align: center;"><span style="color: #999999; font-size: 10pt;"><sup>Table 1. Undocumented functions and byte sequences used by KdcSponge to confirm the correct functions for Windows major version 10.</sup></span></p>
<p>If the domain controller is running Windows Server 2008 or Server 2012 (major version 6), KdcSponge does not reach out to the symbol server and instead will search the entire <span style="font-family: 'courier new', courier, monospace;">kdcsvc.dll</span> module for the byte sequences listed in Table 2 to find the API functions.</p>
<table style="width: 100.116%;">
<tbody>
<tr>
<td style="width: 39.7661%;"><b>Function</b></td>
<td style="width: 105.198%;"><b>Hex bytes</b></td>
</tr>
<tr>
<td style="width: 39.7661%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KdcVerifyEncryptedTimeStamp</span></td>
<td style="width: 105.198%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 F9 48 81 EC C0 00 00 00 48 8B</span></td>
</tr>
<tr>
<td style="width: 39.7661%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KerbHashPasswordEx3</span></td>
<td style="width: 105.198%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 56 41 57 48 8B EC 48 83 EC 40 48 8B F1</span></td>
</tr>
<tr>
<td style="width: 39.7661%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">kdcsvc.KerbFreeKey</span></td>
<td style="width: 105.198%;"><span style="font-weight: 400; font-family: 'courier new', courier, monospace;">40 53 48 83 EC 20 48 8B D9 48 8B 49 10 48 85 C9 0F 85 B4 B9 01 00 33 C0 48 89 03 48 89 43</span></td>
</tr>
</tbody>
</table>
<p style="text-align: center;"><span style="color: #999999;"><sup>Table 2. Undocumented functions and byte sequences used by KdcSponge to locate the sought after functions.</sup></span></p>
<p>Once the <span style="font-family: 'courier new', courier, monospace;">KdcVerifyEncryptedTimeStamp</span>, <span style="font-family: 'courier new', courier, monospace;">KerbHashPasswordEx3</span> and <span style="font-family: 'courier new', courier, monospace;">KerbFreeKey</span> functions are found, the sample will attempt to hook these functions to monitor all calls to them with the intention to steal credentials. When a request to authenticate to the domain controller comes in, these functions in the Kerberos service (KDC service) are called, and the sample will capture the inbound credentials. The credentials are then written to disk at the following location:</p>
<p><span style="font-family: 'courier new', courier, monospace;">%ALLUSERPROFILE%\Microsoft\Windows\Caches\system.dat</span></p>
<p>The stolen credentials are encrypted with a single-byte XOR algorithm using 0x55 as the key and written to the system.dat file one per line in the following structure:</p>
<p><span style="font-family: 'courier new', courier, monospace;">[&lt;timestamp&gt;]&lt;domain&gt;&lt;username&gt; &lt;cleartext password&gt;</span></p>
<h2><a id="post-120911-_hot9433mb07q"></a>Attribution</h2>
<p>While attribution is still ongoing and we have been unable to validate the actor behind the campaign, we did observe some correlations between the tactics and tooling used in the cases we analyzed and Threat Group 3390 (TG-3390, <a href="https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/">Emissary Panda</a>, APT27).</p>
<p>Specifically, as documented by SecureWorks in an article on a <a href="https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage">previous TG-3390 operation</a>, we can see that TG-3390 similarly used web exploitation and another popular Chinese webshell called ChinaChopper for their initial footholds before leveraging legitimate stolen credentials for lateral movement and attacks on a domain controller. While the webshells and exploits differ, once the actors achieved access into the environment, we noted an overlap in some of their exfiltration tooling.</p>
<p>SecureWorks stated the actors were using WinRar masquerading as a different application to split data into RAR archives within the Recycler directory. They provided the following snippet from a Batch file deployed to do this work:</p>
<p><span style="font-family: 'courier new', courier, monospace;">@echo off<br />
</span><span style="font-family: 'courier new', courier, monospace;">c:\windows\temp\svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014 “e:\recycler\REDACTED.rar” “e:\ProgramData\REDACTED\”<br />
</span><span style="font-family: 'courier new', courier, monospace;">Exit</span></p>
<p>From our analysis of recent attacks on ManageEngine ADSelfService Plus, we observed the same technique – with the same order and placement of the parameters passed to a renamed WinRar application.</p>
<p><span style="font-family: 'courier new', courier, monospace;">@echo off<br />
</span><span style="font-family: 'courier new', courier, monospace;">dir %~dp0&gt;&gt;%~dp0\log.txt<br />
</span><span style="font-family: 'courier new', courier, monospace;">%~dp0\vmtools.exe a -k -r -s -m5 -v4096000 -pREDACTED "e:\$RECYCLE.BIN\REDACTED.rar" "E:\Programs\REDACTED\REDACTED"</span></p>
<p>Once the files had been staged, in both cases they were then made accessible on externally facing web servers. The threat actors would then download them through direct HTTP GET requests.</p>
<h2><a id="post-120911-_qyx1akxj07vi"></a>Conclusion</h2>
<p>In September 2021, Unit 42 observed an attack campaign in which the actors gained initial access to targeted organizations by exploiting a recently patched vulnerability in Zoho’s ManageEngine product, ADSelfService Plus, tracked in CVE-2021-40539. At least nine entities across the technology, defense, healthcare, energy and education industries were compromised in this attack campaign.</p>
<p>After exploitation, the threat actor quickly moved laterally through the network and deployed several tools to run commands in order to carry out their post-exploitation activities. The actor heavily relies on the Godzilla webshell, uploading several variations of the open-source webshell to the compromised server over the course of the operation. Several other tools have novel characteristics or have not been publicly discussed as being used in previous attacks, specifically the NGLite backdoor and the KdcSponge stealer. For instance, the NGLite backdoor uses a novel C2 channel involving the decentralized network known as the NKN, while the KdcSponge stealer hooks undocumented functions to harvest credentials from inbound Kerberos authentication attempts to the domain controller.</p>
<p>Unit 42 believes that the actor’s primary goal involved gaining persistent access to the network and the gathering and exfiltration of sensitive documents from the compromised organization. The threat actor gathered sensitive files to a staging directory and created password-protected multi-volume RAR archives in the Recycler folder. The actor exfiltrated the files by directly downloading the individual RAR archives from externally facing web servers.</p>
<p>The following coverages across the Palo Alto Networks platform pertain to this incident:</p>
<ul>
<li>Threat Prevention signature ZOHO corp ManageEngine Improper Authentication Vulnerability was released on Sept. 20 as threat ID 91676.</li>
<li>NGLite backdoor is blocked by Cortex XDR’s local analysis.</li>
<li>All known samples (Dropper, NGLite, KdcSponge) are classified as malware in <a href="https://www.paloaltonetworks.com/products/secure-the-network/wildfire">WildFire</a>.</li>
<li>Cortex Xpanse can accurately identify Zoho ManageEngine ADSelfServicePlus, ManageEngine Desktop Central, or ManageEngine ServiceDeskPlus Servers across customer networks.</li>
</ul>
<p>If you think you may have been impacted, please email <a href="mailto:unit42-investigations@paloaltonetworks.com">unit42-investigations@paloaltonetworks.com</a> or call (866) 486-4842 – (866) 4-UNIT42 – for U.S. toll free, (31-20) 299-3130 in EMEA or (65) 6983-8730 in JAPAC. The <a href="https://www.paloaltonetworks.com/cortex/incident-response">Unit 42 Incident Response</a> team is available 24/7/365.</p>
<p>Special thanks to Unit 42 Consulting Services and the NSA Cybersecurity Collaboration Center for their partnership, collaboration and insights offered in support of this research.</p>
<p>Palo Alto Networks has shared these findings, including file samples and indicators of compromise, with our fellow Cyber Threat Alliance members. CTA members use this intelligence to rapidly deploy protections to their customers and to systematically disrupt malicious cyber actors. Learn more about the <a href="https://www.cyberthreatalliance.org">Cyber Threat Alliance</a>.</p>
<h3><a id="post-120911-_caoc5zqkcqcg"></a>Indicators of Compromise</h3>
<h4><a id="post-120911-_8e5z44xboaep"></a>Dropper SHA256</h4>
<p><span style="font-family: 'courier new', courier, monospace;">b2a29d99a1657140f4e254221d8666a736160ce960d06557778318e0d1b7423b<br />
</span><span style="font-family: 'courier new', courier, monospace;">5fcc9f3b514b853e8e9077ed4940538aba7b3044edbba28ca92ed37199292058</span></p>
<h4><a id="post-120911-_8l1yv4ypnc9k"></a>NGLite SHA256</h4>
<p><span style="font-family: 'courier new', courier, monospace;">805b92787ca7833eef5e61e2df1310e4b6544955e812e60b5f834f904623fd9f </span><br />
<span style="font-family: 'courier new', courier, monospace;">3da8d1bfb8192f43cf5d9247035aa4445381d2d26bed981662e3db34824c71fd<br />
</span><span style="font-family: 'courier new', courier, monospace;">5b8c307c424e777972c0fa1322844d4d04e9eb200fe9532644888c4b6386d755<br />
</span><span style="font-family: 'courier new', courier, monospace;">3f868ac52916ebb6f6186ac20b20903f63bc8e9c460e2418f2b032a207d8f21d</span></p>
<h4><a id="post-120911-_opcet6adkdds"></a>Godzilla Webshell SHA256</h4>
<p><span style="font-family: 'courier new', courier, monospace;">a44a5e8e65266611d5845d88b43c9e4a9d84fe074fd18f48b50fb837fa6e429d<br />
</span><span style="font-family: 'courier new', courier, monospace;">ce310ab611895db1767877bd1f635ee3c4350d6e17ea28f8d100313f62b87382<br />
</span><span style="font-family: 'courier new', courier, monospace;">75574959bbdad4b4ac7b16906cd8f1fd855d2a7df8e63905ab18540e2d6f1600<br />
</span><span style="font-family: 'courier new', courier, monospace;">5475aec3b9837b514367c89d8362a9d524bfa02e75b85b401025588839a40bcb</span></p>
<h4><a id="post-120911-_k53etcn43x5j"></a>KdcSponge SHA256</h4>
<p><span style="font-family: 'courier new', courier, monospace;">3c90df0e02cc9b1cf1a86f9d7e6f777366c5748bd3cf4070b49460b48b4d4090<br />
</span><span style="font-family: 'courier new', courier, monospace;">b4162f039172dcb85ca4b85c99dd77beb70743ffd2e6f9e0ba78531945577665</span></p>
<h4><a id="post-120911-_w3r6gr503pzx"></a>Threat Actor IP Addresses</h4>
<p><span style="font-family: 'courier new', courier, monospace;">24.64.36[.]238<br />
</span><span style="font-family: 'courier new', courier, monospace;">45.63.62[.]109<br />
</span><span style="font-family: 'courier new', courier, monospace;">45.76.173[.]103<br />
</span><span style="font-family: 'courier new', courier, monospace;">45.77.121[.]232<br />
</span><span style="font-family: 'courier new', courier, monospace;">66.42.98[.]156<br />
</span><span style="font-family: 'courier new', courier, monospace;">140.82.17[.]161<br />
</span><span style="font-family: 'courier new', courier, monospace;">149.28.93[.]184<br />
</span><span style="font-family: 'courier new', courier, monospace;">149.248.11[.]205 </span><br />
<span style="font-family: 'courier new', courier, monospace;">199.188.59[.]192</span></p>
<h4><a id="post-120911-_vfrom669nji3"></a>Registry Keys</h4>
<p><span style="font-family: 'courier new', courier, monospace;">Software\Microsoft\Windows\CurrentVersion\Run\ME_ADManager.exe<br />
</span><span style="font-family: 'courier new', courier, monospace;">Software\Microsoft\Windows\CurrentVersion\Run\ME_ADAudit.exe<br />
</span><span style="font-family: 'courier new', courier, monospace;">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\KDC Service</span></p>
<h2><a id="post-120911-_caoc5zqkcqcg"></a>Additional Resources</h2>
<ul>
<li><a href="https://unit42.paloaltonetworks.com/atoms/kdcsponge/">KdcSponge ATOM</a></li>
<li><a href="https://www.microsoft.com/security/blog/2021/11/08/threat-actor-dev-0322-exploiting-zoho-manageengine-adselfservice-plus/"><span style="font-weight: 400;">Threat actor DEV-0322 exploiting ZOHO ManageEngine ADSelfService Plus</span></a></li>
</ul>
      
              </div>
              <span class="post__date">Updated 14 June, 2024 at 12:26 PM PDT</span>
              <button class="l-btn back-to-top" id="backToTop">Back to top</button>
              
			<div class="be__tags-wrapper"> 
				<h3>Tags</h3><ul role="list"><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/advanced-persistent-threat/" role="link" title="Advanced Persistent Threat" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:Advanced Persistent Threat">Advanced Persistent Threat</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/backdoor/" role="link" title="backdoor" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:backdoor">Backdoor</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/credential-harvesting/" role="link" title="Credential Harvesting" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:Credential Harvesting">Credential Harvesting</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/credential-stealer/" role="link" title="credential stealer" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:credential stealer">Credential stealer</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/kdcsponge/" role="link" title="KdcSponge" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:KdcSponge">KdcSponge</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/manageengine/" role="link" title="ManageEngine" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:ManageEngine">ManageEngine</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/nglite/" role="link" title="NGLite" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:NGLite">NGLite</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/tiltedtemple/" role="link" title="TiltedTemple" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:TiltedTemple">TiltedTemple</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/trojan/" role="link" title="Trojan" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:Trojan">Trojan</a></li><li role="listitem"><a href="https://unit42.paloaltonetworks.com/tag/zoho-manageengine/" role="link" title="Zoho ManageEngine" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:tags:Zoho ManageEngine">Zoho ManageEngine</a></li></ul>
			</div> 
              <div class="be__post-nav">
    <a class="prev" href="https://unit42.paloaltonetworks.com" role="link" title="Threat Research" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:article-nav:Threat Research Center"> 
        <span>Threat Research Center</span>
    </a>
            <a class="next" href="https://unit42.paloaltonetworks.com/teamtnt-cryptojacking-watchdog-operations/" role="link" title="Updated: New Evidence Emerges to Suggest WatchDog Was Behind Crypto Campaign" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:article-nav:Updated: New Evidence Emerges to Suggest WatchDog Was Behind Crypto Campaign"> 
            <span>Next: Updated: New Evidence Emerges to Suggest WatchDog Was Behind Crypto Campaign</span>
        </a>
    </div>
 
            </div>
            <div class="be__nav">
            <div class="be__nav-wrapper">
      <div class="be-table-of-contents" data-toc-track="manageengine-godzilla-nglite-kdcsponge:sidebar:table-of-contents">
      <div class="be-title__wrapper">
        <h3>Table of Contents</h3>
      </div> 
            <ul>
        <li></li>
      </ul>
    </div>
   
        <div class="be-related-articles">
        <h3>Related Articles</h3>
        <ul> 
                        <li>
                  <a href="https://unit42.paloaltonetworks.com/operation-diplomatic-specter/" role="link" title="article - table of contents" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:sidebar:related-articles:Operation Diplomatic Specter: An Active Chinese Cyberespionage Campaign Leverages Rare Tool Set to Target Governmental Entities in the Middle East, Africa and Asia">
                      Operation Diplomatic Specter: An Active Chinese Cyberespionage Campaign Leverages Rare Tool Set to Target Governmental Entities in the Middle East, Africa and Asia                  </a>
              </li>
                            <li>
                  <a href="https://unit42.paloaltonetworks.com/cve-2024-3400/" role="link" title="article - table of contents" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:sidebar:related-articles:Threat Brief: Operation MidnightEclipse, Post-Exploitation Activity Related to CVE-2024-3400 (Updated May 20)">
                      Threat Brief: Operation MidnightEclipse, Post-Exploitation Activity Related to CVE-2024-3400 (Updated May 20)                  </a>
              </li>
                            <li>
                  <a href="https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/" role="link" title="article - table of contents" data-page-track="true" data-page-track-value="manageengine-godzilla-nglite-kdcsponge:sidebar:related-articles:ASEAN Entities in the Spotlight: Chinese APT Group Targeting">
                      ASEAN Entities in the Spotlight: Chinese APT Group Targeting                  </a>
              </li>
                      </ul>
      </div>
      </div> 
            </div>
          </div>
        </div>

