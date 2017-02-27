#!/usr/bin/env python 
# -*- coding: utf-8 -*- 

import os,sys,signal
from optparse import OptionParser, OptionGroup
from neko import ESLEvent, tcpdump

class capturePcap(ESLEvent):
	def __init__(self, ip, port, password, debug=False):
		ESLEvent.__init__(self, ip, port, password)

		self.__call = {}
		self.__debug = debug

		# python是无法捕捉kill -9的
		signal.signal(signal.SIGINT, self.__terminate)
		signal.signal(signal.SIGTERM, self.__terminate)
		signal.signal(signal.SIGABRT, self.__terminate)

	def set_pcap(self, protocol='udp', eth='bond0', path='./pcap'):
		self.__protocol = protocol
		self.__eth = eth
		self.__path = path

		# pcap包存放的文件目录
		if not os.path.exists(path):
			os.mkdir(path)

		tcpdump.check(eth)

		return self

	def set_numbers(self, numbers = []):
		self.__numbers = numbers
		return self

	def __terminate(self, *arg):
		ESLEvent.disconnect(self)
		for uuid, call in self.__call.items():
			pcap = call.get("pcap", None)
			if pcap:
				pcap.terminate()
				if self.__debug:
					print("%s tcpdump end %s" % (call.get("id", "0"), call.get("pcap_name", "")))
		else:
			if self.__debug:
				print("\n[end] all\n")
			pass

	def channel_event(self, event):
		event_name = event.getHeader("Event-Name")

		if event_name in ['CHANNEL_CREATE']:
			return self.channel_create(event)
		elif event_name in ['CHANNEL_ANSWER']:
			return self.channel_answer(event) 
		elif event_name in ['CHANNEL_HANGUP']:
			return self.channel_hangup(event) 
		pass

	def __call_time(self, t):
		return t.replace('-', '').replace(' ', '').replace(':', '') if t else None

	def channel_create(self, event):
		
		if self.__debug:
			print(event.getHeader("unique-id"), event.getHeader("Caller-Caller-ID-Number"), event.getHeader("Caller-Destination-Number"), event.getHeader("Caller-Callee-ID-Number"))
		uuid = event.getHeader("unique-id")
		call_dir = event.getHeader("Caller-Direction")

		if call_dir in ['inbound']:
			caller_num = event.getHeader("Caller-Caller-ID-Number")
			callee_num = event.getHeader("Caller-Destination-Number")
			
			if (caller_num in self.__numbers or callee_num in self.__numbers) and uuid not in self.__call:
				session_id = event.getHeader("variable_session_id")

				self.__call[uuid] = {"call":True, "caller_num":caller_num, "callee_num":callee_num,
					"direction":call_dir, "call_time":self.__call_time(event.getHeader("Event-Date-Local")),
					"id": session_id}
				if self.__debug:
					print("\n%s [begin]" % (session_id))
					print("%s locked the number. caller:%s callee:%s" % (session_id, caller_num, callee_num))
		elif call_dir in ['outbound']:
			uuid_other = event.getHeader("Other-Leg-Unique-ID")
			if uuid_other in self.__call and uuid not in self.__call:
				caller_num = event.getHeader("Caller-Caller-ID-Number")
				callee_num = event.getHeader("Caller-Callee-ID-Number")

				self.__call[uuid] = {"call":True, "caller_num":caller_num, "callee_num":callee_num,
					"direction":call_dir, "call_time":self.__call_time(event.getHeader("Event-Date-Local")),
					"id": self.__call[uuid_other].get("id", "0"), "uuid_other": uuid_other if uuid_other else ""}

				info_other = self.__call.get(uuid_other, {})
				if info_other:
					info_other["uuid_other"] = uuid

				if self.__debug:
					print("%s associated the number. caller:%s callee:%s" % (self.__call[uuid]["id"], caller_num, callee_num))

	def channel_answer(self, event):
		uuid = event.getHeader("unique-id")

		call = self.__call.get(uuid, None)
		if not call:
			return 

		local_media_ip = event.getHeader("variable_local_media_ip")
		local_media_port = event.getHeader("variable_local_media_port")
		remote_media_ip = event.getHeader("variable_remote_media_ip")
		remote_media_port = event.getHeader("variable_remote_media_port")

		call["local_media_ip"] = local_media_ip
		call["local_media_port"] = local_media_port
		call["remote_media_ip"] = remote_media_ip
		call["remote_media_port"] = remote_media_port

		pcap_name = "_".join([call.get("id", "0"), call.get("caller_num", ""), call.get("callee_num", ""), call.get("direction", ""), call.get("call_time", "")]) + ".pcap"

		# 这里会创建子进程
		pcap = tcpdump(self.__protocol, self.__eth, os.path.join(self.__path, pcap_name), int(local_media_port), debug=self.__debug)
		if pcap.run():
			
			if self.__debug:
				print("%s tcpdump begin %s on %s port(src&dst) %s" % (call.get("id", "0"), pcap_name, self.__eth, local_media_port))
			call["pcap"] = pcap
			call["pcap_name"] = pcap_name
		else:
			if self.__debug:
				print("%s tcpdump failed %s on %s port(src&dst) %s" % (call.get("id", "0"), pcap_name, self.__eth, local_media_port))
			pass

	def channel_hangup(self, event):
		uuid = event.getHeader("unique-id")

		call = self.__call.get(uuid, None)
		if not call:
			return 

		pcap = call.get("pcap", None)
		if pcap:
			pcap.terminate()
			if self.__debug:
				print("%s tcpdump end %s" % (call.get("id", "0"), call.get("pcap_name", "")))
			
		
		if self.__debug and not self.__call.get(call.get("uuid_other", ""), {}):
			print("%s [end]\n" % (call.get("id", "0")))

		del self.__call[uuid]



if __name__ == '__main__':

	usage = "usage: \n\tpython %prog [options]" + \
		"\nFor example: \n\tpython %prog --num1 18682099276 [-i eth0] [-s 10.9.0.108] [-p 8021] [-a ClueCon]" + \
		"\n\tpython %prog --num1 18682099276 --num2 13798283294 [-i eth0] [-s 10.9.0.108] [-p 8021] [-a ClueCon]" 
	parser = OptionParser(usage=usage, version="%prog V1.0")
	parser.add_option('-s', '--host', dest='host', default='localhost',help="ESL IP. default:'%default'")
	parser.add_option('-p', '--port', dest='port', default='8021', help="ESL port. default:'%default'")
	parser.add_option('-a', '--password', dest='password', default='ClueCon', help="ESL password. default:'%default'")
	
	# 需要抓包的网卡
	parser.add_option('-i', '--eth', dest='eth', default='bond0', help="capture RTP on which eth. default:'%default'")

	group = OptionGroup(parser, "List Options", "monitor numbers(but just only one will be monitored in same time)")
	max_num = 20
	for i in range(1, max_num + 1):
		group.add_option('--num%d' % i, dest='num%d' % i, default='', help="monitor number%d" % i)
	else:
		parser.add_option_group(group)  
	
	(options, args) = parser.parse_args()

	# 至少需要1个号码
	num_list = filter(lambda x: x != '', [eval('options.num%d' % x) for x in range(1, max_num + 1)])
	if not num_list:
		print("no any number to be monitored")
		os.sys.exit(0)
	else:
		print("number monitored list:%s" % num_list)

	p = capturePcap(options.host, options.port, options.password, debug=True)
	p.set_pcap(eth=options.eth).set_numbers(num_list)
	p.run(36000)
	

	





