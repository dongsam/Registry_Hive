#coding: euc-kr




import sys
import re
import os
from struct import pack, unpack
import time
import datetime



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
	nk = s.find("nk",int(addr,0))
	namelen=edian4(s,nk+72,0,0)		# nk매직넘버 72바이트 뒤에 있는 키네임 길이값을 가져온다  
	nk += 4							#NK매직넘버 offset을 찾아서 4바이트 뒤에있는 NT time 위치로 이동 
	timestamp=edian8(s,nk,1,0)		# 리틀에디안으로 바꿔서 hex로 출력 
	
	nk += 72
	
	wf.write(s[nk:nk+namelen])
	wf.write("				")
	wf.write(str(getNTtime(timestamp)))   # 아까 읽은 timestamp값을 함수를 통해 마지막 쓰여진 시간 획득  
	wf.write("(UCT)\r\n")
	
#for file in sys.argv[1:]:	
f=open("SYSTEM","rb")
wf=open("services.txt","wb")

filesize=os.path.getsize("SYSTEM")	
#print "This SYSTEM file is %d byte" % filesize		

s=f.read()
services=s.find("services")	# services 스트링이 존재하는 0x1220 의 offset값
f.seek(services)			# 해당 offset값으로 이동 
f.seek(-56,1)				# NK레코드에서 마지막 key name 56바이트 전에 subkey개가 존재하므로 -56 이동 
subkeyCnt = edian4(s, f.tell(),0,0)		# subkey개수 획득 
f.seek(8,1)							# NK레코드에서 마지막 key name 48바이트 전에 subkeylist의 pointer가 존재하므로 +8 이동 
listpoint=edian4(s,f.tell(),0,1)	# sublist pointer로 이동하여 리틀에디안 적용 및 +1000  한 값 얻기 
f.seek(listpoint)					# 해당 sublist pointer로 이동 
#print hex(f.tell())					
lh=s.find("lh",f.tell())			# sublist pointer에서 magic number인 lh를 찾기 
f.seek(lh+4)							# subkeylist가 존재하는  lh magicnumber에서 4바이트 뒤로  이동 
#print hex(f.tell())

#nk=s.find("nk",f.tell())	# 현재 offset값 위치에서부 nk 를 탐색 
#f.seek(nk)					# 해당 offset 값으로 이동 




wf.write("---------------------------------------------------------------\r\n") 
wf.write("Service name				last written time\r\n")

while 1 :
	if 1 >= subkeyCnt : break
	addr = edian4(s,f.tell(),1,1)
	getSubkey(s,addr)
	f.seek(8,1)
	subkeyCnt-=1

wf.write("---------------------------------------------------------------\r\n")

"""
#while 1:					
ch=f.read(filesize)
if not ch: break
f.write(ch)
"""
f.close()
wf.close()



################################################################
# BOB 1기 변동삼, 모든 코드는 직접 작성하였음을 밝힙니다. 			  #
###############################################################

