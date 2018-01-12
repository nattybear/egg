#!/usr/bin/python3

from sys import argv
from struct import unpack

def addComma(n):
	n = str(n)
	if len(n) < 4: return n
	n = n[:-3] + ',' + n[-3:]
	return n

def b2h(b):
	t = tuple(b)
	l = list(map(hex, t))
	l = [i[2:].zfill(2) for i in l]
	return ' '.join(l)

def EggHeader():
	ver = f.read(2)
	hid = f.read(4)
	res = f.read(4)
	print('[*] EGG Header')
	print('    [-] Version :', b2h(ver))
	print('    [-] Header ID :', b2h(hid))
	print('    [-] Reserved :', b2h(res))

def FileHeader():
	fid = f.read(4)
	flen = f.read(8)
	flen = unpack('Q', flen)[0]
	print('[*] File Header')
	print('    [-] File ID :', b2h(fid))
	print('    [-] File Length :', addComma(flen))

def FileName():
	flag = f.read(1)
	size = unpack('H', f.read(2))[0]
	name = f.read(size).decode('utf-8')
	print('[*] File Name')
	print('    [-] Bit Flag :', b2h(flag))
	print('    [-] Size :', addComma(size))
	print('    [-] Name :', name)

def EOFARC():
	pass

def WindowsFileInformation():
	flag = f.read(1)
	size = unpack('H', f.read(2))[0]
	time = f.read(8)
	attrib = f.read(1)
	print('[*] Windows File Information')
	print('    [-] Bit flag :', b2h(flag))
	print('    [-] Size :', addComma(size))
	print('    [-] Last Midified DataTime :', b2h(time))
	print('    [-] Attribute :', b2h(attrib))

def BlockHeader():
	compm = f.read(1)
	comph = f.read(1)
	uncompsize = unpack('I', f.read(4))[0]
	compsize = unpack('I', f.read(4))[0]
	crc32 = f.read(4)
	f.read(4) # EOFARC
	compdata = f.read(compsize)
	
	print('[*] Block Header')
	print('    [-] Compress Method(M) :', b2h(compm))
	print('    [-] Compress Method(H) :', b2h(comph))
	print('    [-] Uncompress Size :', addComma(uncompsize))
	print('    [-] Compress Size :', addComma(compsize))
	print('    [-] CRC32 :', b2h(crc32))

sig =	{
		b'\x45\x47\x47\x41' : EggHeader,
		b'\xe3\x90\x85\x0a' : FileHeader,
		b'\x22\x82\xe2\x08' : EOFARC,
		b'\xac\x91\x85\x0a' : FileName,
		b'\x0b\x95\x86\x2c' : WindowsFileInformation,
		b'\x13\x0c\xb5\x02' : BlockHeader
	}

if __name__ == '__main__':
	f = open(argv[1], 'rb')
	while 1:
		b = f.read(4)
		if len(b) == 0: break
		try:
			sig[b]()
		except KeyError as e:
			break
