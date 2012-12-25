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
	nk = s.find("nk",int(addr,0))
	namelen=edian4(s,nk+72,0,0)		# nk�����ѹ� 72����Ʈ �ڿ� �ִ� Ű���� ���̰��� �����´�  
	nk += 4							#NK�����ѹ� offset�� ã�Ƽ� 4����Ʈ �ڿ��ִ� NT time ��ġ�� �̵� 
	timestamp=edian8(s,nk,1,0)		# ��Ʋ��������� �ٲ㼭 hex�� ��� 
	
	nk += 72
	
	wf.write(s[nk:nk+namelen])
	wf.write("				")
	wf.write(str(getNTtime(timestamp)))   # �Ʊ� ���� timestamp���� �Լ��� ���� ������ ������ �ð� ȹ��  
	wf.write("(UCT)\r\n")
	
#for file in sys.argv[1:]:	
f=open("SYSTEM","rb")
wf=open("services.txt","wb")

filesize=os.path.getsize("SYSTEM")	
#print "This SYSTEM file is %d byte" % filesize		

s=f.read()
services=s.find("services")	# services ��Ʈ���� �����ϴ� 0x1220 �� offset��
f.seek(services)			# �ش� offset������ �̵� 
f.seek(-56,1)				# NK���ڵ忡�� ������ key name 56����Ʈ ���� subkey���� �����ϹǷ� -56 �̵� 
subkeyCnt = edian4(s, f.tell(),0,0)		# subkey���� ȹ�� 
f.seek(8,1)							# NK���ڵ忡�� ������ key name 48����Ʈ ���� subkeylist�� pointer�� �����ϹǷ� +8 �̵� 
listpoint=edian4(s,f.tell(),0,1)	# sublist pointer�� �̵��Ͽ� ��Ʋ����� ���� �� +1000  �� �� ��� 
f.seek(listpoint)					# �ش� sublist pointer�� �̵� 
#print hex(f.tell())					
lh=s.find("lh",f.tell())			# sublist pointer���� magic number�� lh�� ã�� 
f.seek(lh+4)							# subkeylist�� �����ϴ�  lh magicnumber���� 4����Ʈ �ڷ�  �̵� 
#print hex(f.tell())

#nk=s.find("nk",f.tell())	# ���� offset�� ��ġ������ nk �� Ž�� 
#f.seek(nk)					# �ش� offset ������ �̵� 




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
# BOB 1�� ������, ��� �ڵ�� ���� �ۼ��Ͽ����� �����ϴ�. 			  #
###############################################################

