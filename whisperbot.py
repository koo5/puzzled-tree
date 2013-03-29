#!/usr/bin/python
file = open("wlog.txt", "a")
from config import *
import string
import select
import socket
import struct
import time
import sys
import re
import os
from time import strftime as date
#import random

mapserv = None

# http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
console_width = int(os.popen('stty size', 'r').read().split()[1])

packet_lengths = [
	10,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
#0x0040
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  50,  3, -1, 55, 17,  3, 37, 46, -1, 23, -1,  3,108,  3,  2,
	3, 28, 19, 11,  3, -1,  9,  5, 54, 53, 58, 60, 41,  2,  6,  6,
#0x0080
	7,  3,  2,  2,  2,  5, 16, 12, 10,  7, 29, 23, -1, -1, -1,  0,
	7, 22, 28,  2,  6, 30, -1, -1,  3, -1, -1,  5,  9, 17, 17,  6,
	23,  6,  6, -1, -1, -1, -1,  8,  7,  6,  7,  4,  7,  0, -1,  6,
	8,  8,  3,  3, -1,  6,  6, -1,  7,  6,  2,  5,  6, 44,  5,  3,
#0x00C0
	7,  2,  6,  8,  6,  7, -1, -1, -1, -1,  3,  3,  6,  6,  2, 27,
	3,  4,  4,  2, -1, -1,  3, -1,  6, 14,  3, -1, 28, 29, -1, -1,
	30, 30, 26,  2,  6, 26,  3,  3,  8, 19,  5,  2,  3,  2,  2,  2,
	3,  2,  6,  8, 21,  8,  8,  2,  2, 26,  3, -1,  6, 27, 30, 10,
#0x0100
	2,  6,  6, 30, 79, 31, 10, 10, -1, -1,  4,  6,  6,  2, 11, -1,
	10, 39,  4, 10, 31, 35, 10, 18,  2, 13, 15, 20, 68,  2,  3, 16,
	6, 14, -1, -1, 21,  8,  8,  8,  8,  8,  2,  2,  3,  4,  2, -1,
	6, 86,  6, -1, -1,  7, -1,  6,  3, 16,  4,  4,  4,  6, 24, 26,
#0x0140
	22, 14,  6, 10, 23, 19,  6, 39,  8,  9,  6, 27, -1,  2,  6,  6,
	110,  6, -1, -1, -1, -1, -1,  6, -1, 54, 66, 54, 90, 42,  6, 42,
	-1, -1, -1, -1, -1, 30, -1,  3, 14,  3, 30, 10, 43, 14,186,182,
	14, 30, 10,  3, -1,  6,106, -1,  4,  5,  4, -1,  6,  7, -1, -1,
#0x0180
	6,  3,106, 10, 10, 34,  0,  6,  8,  4,  4,  4, 29, -1, 10,  6,
	90, 86, 24,  6, 30,102,  9,  4,  8,  4, 14, 10,  4,  6,  2,  6,
	3,  3, 35,  5, 11, 26, -1,  4,  4,  6, 10, 12,  6, -1,  4,  4,
	11,  7, -1, 67, 12, 18,114,  6,  3,  6, 26, 26, 26, 26,  2,  3,
#0x01C0
	2, 14, 10, -1, 22, 22,  4,  2, 13, 97,  0,  9,  9, 29,  6, 28,
	8, 14, 10, 35,  6,  8,  4, 11, 54, 53, 60,  2, -1, 47, 33,  6,
	30,  8, 34, 14,  2,  6, 26,  2, 28, 81,  6, 10, 26,  2, -1, -1,
	-1, -1, 20, 10, 32,  9, 34, 14,  2,  6, 48, 56, -1,  4,  5, 10,
#0x2000
	26,  0,  0,  0, 18,  0,  0,  0,  0,  0,  0, 19,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
]

class PacketBuffer:
	def __init__(self):
		self.buff = ""

	def feed(self, data):
		self.buff += data

	def drop(self, count):
		self.buff = self.buff[count:]

	def __iter__(self):
		return self

	def next(self):
		if len(self.buff) < 2:
			raise StopIteration

		pkttype = struct.unpack("<H", self.buff[:2])[0]
		assert pkttype < len(packet_lengths)
		assert packet_lengths[pkttype] != 0
		if packet_lengths[pkttype] < 0:
			if len(self.buff) < 4:
				raise StopIteration
			pktlen = struct.unpack("<H", self.buff[2:4])[0]
			assert pktlen >= 4
		else:
			pktlen = packet_lengths[pkttype]

		if len(self.buff) < pktlen:
			raise StopIteration
		packet = self.buff[:pktlen]
		self.buff = self.buff[pktlen:]
		return packet

def parse_ip(s):
	return ".".join(map(str, map(ord, s)))

def whisper(nick, message):
	return "\x96\0%s%s%s" % (struct.pack("<H", len(message)+28), nick.ljust(24, '\0'), message)

def smile(number):
	mapserv.sendall("\xbf\0"+(chr(number)))

def say(message):
	data = "%s : %s" % (charactername, message)
	mapserv.sendall("\x8c\0%s%s" % (struct.pack("<H", len(data)+4), data))
	file.write("[" + date('%H:%M:%S') + "] " + "Me: " + message + "\n")

def main():
	global mapserv
	login = socket.socket()
	login.connect((server, port))
	print("login connected")
	login.sendall("\x64\0\0\0\0\0%s%s\0" % (account.ljust(24, '\0'), password.ljust(24, '\0')))

	pb = PacketBuffer()
	id1 = accid = id2 = sex = 0
	charip = ""
	charport = 0
	while True:
		data = login.recv(1500)
		if not data:
			break
		pb.feed(data)
		for packet in pb:
			if packet.startswith("\x69\0"): # login succeeded
				id1, accid, id2 = struct.unpack("<LLL", packet[4:16])
				sex = ord(packet[46])
				packet = packet[47:]
				charip = parse_ip(packet[:4])
				charport = struct.unpack("<H", packet[4:6])[0]
				login.close()
				break
		if charip:
			break

	assert charport

	char = socket.socket()
	char.connect((charip, charport))
	print("char connected")
	char.sendall("\x65\0%s\0\0%s" % (struct.pack("<LLL", accid, id1, id2), chr(sex)))
	char.recv(4)

	pb = PacketBuffer()
	mapip = ""
	mapport = 0
	charid = 0
	while True:
		data = char.recv(1500)
		if not data:
			break
		pb.feed(data)
		for packet in pb:
			if packet.startswith("\x6b\0"):
				char.sendall("\x66\0%s" % chr(character))
			elif packet.startswith("\x71\0"):
				charid = struct.unpack("<L", packet[2:6])[0]
				mapip = parse_ip(packet[22:26])
				mapport = struct.unpack("<H", packet[26:28])[0]
				char.close()
				break
		if mapip:
			break

	assert mapport

	mapserv = socket.socket()
	mapserv.connect((mapip, mapport))
	print("map connected")
	mapserv.sendall("\x72\0%s" % struct.pack("<LLLLB", accid, charid, id1, id2, sex))
	mapserv.recv(4)

	mapserv.setblocking(0)
	mapserv.settimeout(0.1)

	pb = PacketBuffer()
	gotresponse = set()

	while True:
		si,so,se = select.select([sys.stdin],[],[], 0.1)
		for s in si:
			if s == sys.stdin:
				message = sys.stdin.readline()[:-1]
				if len(message) > 0:
					if message[0] == '/':
						if len(message) > 1:
							if (message[1] == 'q') or (message[1] == 'w'):
								nick = string.split(message)[1]
								text = string.join(string.split(message)[2:])
								mapserv.sendall(whisper(nick, text))
								break
							elif ord(message[1]) in range(ord('1'), ord('9')):
								smile(ord(message[1]) - ord('0'))
								break
				say(message)

		try:
			data = mapserv.recv(1500)
			if not data:
				break#exit

			pb.feed(data)
			for packet in pb:
#				print [hex(ord(x)) for x in packet]
				if packet.startswith("\x73\0"): # connected
					mapserv.sendall("\x7d\0") # map loaded
					if sit:
						mapserv.sendall("\x89\0\0\0\0\0\x02") # sit
					smile(2)

				elif packet.startswith("\xc0\0"): #smiley
					if packet[6] == '\2':
#						if random.randint(0,1) == 1:
						print "o_0"
						time.sleep(0.5)
						smile(2)
#						else:
#							print "pffft"

				elif packet.startswith("\x8e\0"): # server speech
					message = packet[4:]
					print "[" + date('%H:%M:%S') + "] " + message
					if "automaticly banned for spam" in message:
						time.sleep(3)
				elif packet.startswith("\x8d\0"): # char speech
					message = re.sub(r'(##[0-9])',color_replacement_regex,packet[8:-1])
					print "[" + date('%H:%M:%S') + "] " + message
					if len(message) > console_width:
						print ""
					file.write("[" + date('%H:%M:%S') + "] " + message + "\n")
					#file.flush()
#					if (" : "+charactername.lower()) in message.lower():
					(nick, msg) = message.split(" : ")
					msg = msg.lower()
					if msg.startswith(charactername.lower()):
						if "shut up" in msg:
							say("i can't do that yet:(")
						if "help" in msg or "daddy" in msg or "mommy" in msg:
							say("[@@https://github.com/koo5/puzzled-tree/blob/master/whisperbot.py |https://github.com/koo5/puzzled-tree/blob/master/whisperbot.py@@]")
					
					
					time.sleep(0.1)

				elif packet.startswith("\x97\0"):#a whisper
					nick = packet[4:28].rstrip("\0")
					message = packet[28:]
					file.write("[" + date('%H:%M:%S') + "] " + "!!! " + nick + ": " + message + "\n")
					print "[" + date('%H:%M:%S') + "] " + "!!! " + nick + ": " + message


		except socket.timeout:
			pass


if __name__ == '__main__':
	main()
file.close()