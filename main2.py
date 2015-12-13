#coding: euc-kr

import sys
import re
import os
from struct import pack, unpack
import time
import datetime
import codecs

tabCount=-1


def edian2(s, addr, type):		# big edian16비트를 	little edian으로 변경해주는 함수 		
											# type이 0이면 int로 return 1이면 hex로 return 
											
	a,b = s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b
	result = int(result,0)
	if not type:
		return result
	else:
		return hex(result)
	
def edian4(s, addr, type, plus1000):		# big edian32비트를 	little edian으로 변경해주는 함수 		
											# type이 0이면 int로 return 1이면 hex로 return 
											# plus1000이 1이면 +(0x4096) 0이면 그대로  
	a,b,c,d = s[addr+3].encode('hex'), s[addr+2].encode('hex'), s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b+c+d
	result = int(result,0)
	if plus1000 :
		result+=4096
	if not type:
		return result
	else:
		return hex(result)
	
def edian8(s, addr, type, plus1000):		# big edian 64비트	little edian으로 변경해주는 함수 		
											# type이 0이면 int로 return 1이면 hex로 return 
											# plus1000이 1이면 +(0x4096) 0이면 그대로  
	a,b,c,d,e,f,g,h = s[addr+7].encode('hex'), s[addr+6].encode('hex'), s[addr+5].encode('hex'), s[addr+4].encode('hex'), s[addr+3].encode('hex'), s[addr+2].encode('hex'), s[addr+1].encode('hex'), s[addr].encode('hex')
	result = "0x"+a+b+c+d+e+f+g+h
	result = int(result,0)
	if plus1000 :
		result+=4096
	if not type:
		return result
	else:
		return hex(result)	
	
	

def getNTtime(dt):				# 64비트 NT time stamp를 hex 64비트로 입력받아 날짜로 출력해주는 함수 
    microseconds = int(dt, 16) / 10
    seconds, microseconds = divmod(microseconds, 1000000)
    days, seconds = divmod(seconds, 86400)
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds)
	
	
	
def getSubkey(s,addr):			# subkey 의 주소를 받아서 이름과 NT time을 출력해주는 함수 
	global tabCount
	nk = s.find("nk",int(addr,0))
	services=nk
	namelen=edian4(s,nk+72,0,0)		# nk매직넘버 72바이트 뒤에 있는 키네임 길이값을 가져온다  
	nk += 4							#NK매직넘버 offset을 찾아서 4바이트 뒤에있는 NT time 위치로 이동 
	timestamp=edian8(s,nk,1,0)		# 리틀에디안으로 바꿔서 hex로 출력 
	dataCount = edian4(s,services+36,0,0)	# nk 매직넘버에서 36바이트 뒤에있는 vk데이터의 개수를 읽어온다 
	dataList = edian4(s,services+40,0,1)##################################
	nk += 72								# 맨마지막의 nk의 이름부분으로 이동 
	nk_to=nk		
	#wf.write(hex(services)+"	")
	tabCount+=1	
	tabi=tabCount
	while tabi:						
		wf.write("	")
		tabi-=1
	tabi=tabCount
	wf.write(s[nk:nk+namelen])		# name 출력  namelen 길이만큼  
	wf.write("	")
	#wf.write(str(dataCount))		#디버깅을 위한 출력 
	#wf.write(" "+hex(dataList))
	getvkdata(s,dataList,dataCount)
	wf.write("	\r\n")
	
	forwardSubkey(s,services)
	tabCount-=1

def getvkdata(s,dataList,dataCount):		#  vk레코드를 파싱해서 출력해주는 함수 
	global tabCount								#트리구조를 형성할 탭을 글로벌변수로 선언  
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
		
						
		wf.write("\r\n")								#탭으로 트리구조 형성  
		tabCount+=4
		tabi=tabCount
		while tabi:						
			wf.write("	")
			tabi-=1
		tabi=tabCount
		tabCount-=4
		
		
		wf.write("	"+dataname+"	")
		#wf.write(" "+hex(datatype))					#디버깅을 위한 출력  
		#wf.write(" "+str(datalen)+" ")					#디버깅을 위한 출력  
		realdata=""
		
		if datatype==4:									##vk 레코드값중 해당 값의 인코딩 옵션에 따른 출력 설
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
	subkeyCnt = edian4(s, services,0,0)		# subkey개수 획득 		
	services+=8								# NK레코드에서 마지막 key name 48바이트 전에 subkeylist의 pointer가 존재하므로 +8 이동 
	listpoint=edian4(s,services,0,1)	# sublist pointer로 이동하여 리틀에디안 적용 및 +1000  한 값 얻기 
	lh=s.find("lh",listpoint)			# sublist pointer에서 magic number인 lh를 찾기  
	lh+=4								# subkeylist가 존재하는  lh magicnumber에서 4바이트 뒤로  이동
	
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
services=s.find("services")	# services 스트링이 존재하는 0x1220 의 offset값
f.seek(services)			# 해당 offset값으로 이동 
services-=76				# NK레코드에서 마지막 key name 76바이트 전에 nk 매직넘버가 존재하므로 -76만큼 이동  
forwardSubkey(s,services)



f.close()
wf.close()


################################################################
# BOB 1기 변동삼, 모든 코드는 직접 작성하였음을 밝힙니다. 			  #
###############################################################



