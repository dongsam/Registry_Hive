#coding: euc-kr


################################################################
# BOB 1�� ������, ��� �ڵ�� ���� �ۼ��Ͽ����� �����ϴ�. 			  #
###############################################################


import sys
import re
import os
from struct import pack, unpack
import time
import datetime
import codecs

tabCount=-1


def edian2(s, addr, type):		# big edian16��Ʈ�� 	little edian���� �������ִ� �Լ� 		
											# type�� 0�̸� int�� return 1�̸� hex�� return 
											
	a,b = s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b
	result = int(result,0)
	if not type:
		return result
	else:
		return hex(result)
	
def edian4(s, addr, type, plus1000):		# big edian32��Ʈ�� 	little edian���� �������ִ� �Լ� 		
											# type�� 0�̸� int�� return 1�̸� hex�� return 
											# plus1000�� 1�̸� +(0x4096) 0�̸� �״��  
	a,b,c,d = s[addr+3].encode('hex'), s[addr+2].encode('hex'), s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b+c+d
	result = int(result,0)
	if plus1000 :
		result+=4096
	if not type:
		return result
	else:
		return hex(result)
	
def edian8(s, addr, type, plus1000):		# big edian 64��Ʈ	little edian���� �������ִ� �Լ� 		
											# type�� 0�̸� int�� return 1�̸� hex�� return 
											# plus1000�� 1�̸� +(0x4096) 0�̸� �״��  
	a,b,c,d,e,f,g,h = s[addr+7].encode('hex'), s[addr+6].encode('hex'), s[addr+5].encode('hex'), s[addr+4].encode('hex'), s[addr+3].encode('hex'), s[addr+2].encode('hex'), s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b+c+d+e+f+g+h
	result = int(result,0)
	if plus1000 :
		result+=4096
	if not type:
		return result
	else:
		return hex(result)	
	
	

def getNTtime(dt):				# 64��Ʈ NT time stamp�� hex 64��Ʈ�� �Է¹޾� ��¥�� ������ִ� �Լ� 
    microseconds = int(dt, 16) / 10
    seconds, microseconds = divmod(microseconds, 1000000)
    days, seconds = divmod(seconds, 86400)
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds)
	
	
	
def getSubkey(s,addr):			# subkey �� �ּҸ� �޾Ƽ� �̸��� NT time�� ������ִ� �Լ� 
	global tabCount
	nk = s.find("nk",int(addr,0))
	services=nk
	namelen=edian4(s,nk+72,0,0)		# nk�����ѹ� 72����Ʈ �ڿ� �ִ� Ű���� ���̰��� �����´�  
	nk += 4							#NK�����ѹ� offset�� ã�Ƽ� 4����Ʈ �ڿ��ִ� NT time ��ġ�� �̵� 
	timestamp=edian8(s,nk,1,0)		# ��Ʋ��������� �ٲ㼭 hex�� ��� 
	dataCount = edian4(s,services+36,0,0)	# nk �����ѹ����� 36����Ʈ �ڿ��ִ� vk�������� ������ �о�´� 
	dataList = edian4(s,services+40,0,1)##################################
	nk += 72								# �Ǹ������� nk�� �̸��κ����� �̵� 
	nk_to=nk		
	#wf.write(hex(services)+"	")
	tabCount+=1	
	tabi=tabCount
	while tabi:						
		wf.write("	")
		tabi-=1
	tabi=tabCount
	wf.write(s[nk:nk+namelen])		# name ���  namelen ���̸�ŭ  
	wf.write("	")
	#wf.write(str(dataCount))		#������� ���� ��� 
	#wf.write(" "+hex(dataList))
	getvkdata(s,dataList,dataCount)
	wf.write("	\r\n")
	
	forwardSubkey(s,services)
	tabCount-=1

def getvkdata(s,dataList,dataCount):		#  vk���ڵ带 �Ľ��ؼ� ������ִ� �Լ� 
	global tabCount								#Ʈ�������� ������ ���� �۷ι������� ����  
	while dataCount:
		dataList+=4
		services=edian4(s,dataList,0,1)
		services=s.find("vk",services+1)
		hexcode = "	"+hex(services)
		namelen = edian2(s,services+2,0)
		datalen = edian4(s,services+4,0,0)
		dataAddr= edian4(s,services+8,0,1)
		datatype= edian4(s,services+12,0,0)
		dataname= s[services+20:services+20+namelen]
		
						
		wf.write("\r\n")								#������ Ʈ������ ����  
		tabCount+=4
		tabi=tabCount
		while tabi:						
			wf.write("	")
			tabi-=1
		tabi=tabCount
		tabCount-=4
		
		
		wf.write("	"+dataname+"	")
		#wf.write(" "+hex(datatype))					#������� ���� ���  
		#wf.write(" "+str(datalen)+" ")					#������� ���� ���  
		realdata=""
		
		if datatype==4:									##vk ���ڵ尪�� �ش� ���� ���ڵ� �ɼǿ� ���� ��� ��
			wf.write(" "+hex(dataAddr-4096))
		elif datatype==3:
			if datalen>1500: datalen=1500
			realdata=s[dataAddr+4:dataAddr+4+datalen].encode('hex')
			wf.write(str(realdata))
		elif datatype==7:
			if datalen>1500: datalen=1500
			for i in range(datalen/2):
				realdata=s[dataAddr+4+i*2].encode('hex')
				wf.write(str(realdata))	
		else:
			if datalen>1500: datalen=1500
			for i in range(datalen/2):
				realdata=s[dataAddr+4+i*2].encode('hex')
				wf.write(str(realdata))	
		dataCount -= 1
		
		
	

def forwardSubkey(s,services):
	global tabCount
	services+=20
	subkeyCnt = edian4(s, services,0,0)		# subkey���� ȹ�� 		
	services+=8								# NK���ڵ忡�� ������ key name 48����Ʈ ���� subkeylist�� pointer�� �����ϹǷ� +8 �̵� 
	listpoint=edian4(s,services,0,1)	# sublist pointer�� �̵��Ͽ� ��Ʋ����� ���� �� +1000  �� �� ��� 
	lh=s.find("lh",listpoint)			# sublist pointer���� magic number�� lh�� ã��  
	lh+=4								# subkeylist�� �����ϴ�  lh magicnumber���� 4����Ʈ �ڷ�  �̵�
	
	while 1 :
		if 0 >= subkeyCnt : break
		addr = edian4(s,lh,1,1)
		getSubkey(s,addr)
		lh+=8
		subkeyCnt-=1
	

	
f=open("SYSTEM","rb")
wf=open("services_key_value_data.txt","wb")

filesize=os.path.getsize("SYSTEM")	

s=f.read()
services=s.find("services")	# services ��Ʈ���� �����ϴ� 0x1220 �� offset��
f.seek(services)			# �ش� offset������ �̵� 
services-=76				# NK���ڵ忡�� ������ key name 76����Ʈ ���� nk �����ѹ��� �����ϹǷ� -76��ŭ �̵�  
forwardSubkey(s,services)



f.close()
wf.close()


################################################################
# BOB 1�� ������, ��� �ڵ�� ���� �ۼ��Ͽ����� �����ϴ�. 			  #
###############################################################



