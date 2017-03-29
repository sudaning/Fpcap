#!/usr/bin/env python 
# -*- coding: utf-8 -*- 

import os,sys,signal
from optparse import OptionParser, OptionGroup
from neko import ESLEvent, tcpdump

class capturePcap(ESLEvent):
	"""
	按照号码监听呼叫信息，提取其中RTP流的协商端口(本端和对端)，利用tcpdump对这两个端口进行抓包
	"""
	def __init__(self, ip, port, password, debug=False):
		try:
			ESLEvent.__init__(self, ip, port, password)
		except Exception as err:
			raise Exception(err)
			
		self.__call = {}
		self.__debug = debug

		# tcpdump抓包时，是开启子进程，这里需要监听kill命令，以便顺利结束掉已经开启的进程
		signal.signal(signal.SIGINT, self.__terminate)
		signal.signal(signal.SIGTERM, self.__terminate)
		signal.signal(signal.SIGABRT, self.__terminate)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, exc_tb):
		if exc_tb:
			return False
		else:
			self.__del__()

	def __del__(self):
		self.__terminate()

	def set_pcap(self, protocol='udp', eth='bond0', path='./pcap'):
		"""
		设置抓包相关信息.
		 
		参数:
		  protocol - 协议类型
		  eth - 网卡
		  path - 保存路径(相对于运行路径)
		返回值:
		  类对象本身(方便链式表达)
		 
		异常:
		  无
		"""
		self.__protocol = protocol
		self.__eth = eth
		self.__path = path

		# pcap包存放的文件目录
		if not os.path.exists(path):
			os.mkdir(path)

		tcpdump.check(eth)

		return self

	def set_monitor_numbers(self, numbers = []):
		"""
		设置需要监听的号码(主叫和被叫).
		 
		参数:
		  numbers - 号码列表
		返回值:
		  类对象本身(方便链式表达)
		 
		异常:
		  无
		"""
		self.__monitor_numbers = numbers
		return self

	def run(self, timeout=-1):
		"""
		开始监听号码，并在识别到号码后呼叫建立时抓包
		 
		参数:
		  timeout - 监听时长
		返回值:
		  ESLEvent.run的返回值
		 
		异常:
		  无
		"""
		return ESLEvent.run(self, timeout)

	def __terminate(self, *arg):
		"""
		终止程序，停止相关抓包的子线程
		 
		参数:
		  arg - 参数
		返回值:
		  无
		 
		异常:
		  无
		"""
		ESLEvent.disconnect(self)
		for uuid, call in self.__call.items():
			pcap = call.get("pcap", None)
			if pcap:
				pcap.terminate()
				print("%s tcpdump end %s" % (call.get("id", "0"), call.get("pcap_name", "")))
		else:
			if self.__debug:
				print("\n[end] all\n")
			pass

	def channel_event(self, event):
		"""
		覆盖父类的channel_event方法，截取通道事件
		 
		参数:
		  event - 事件
		返回值:
		  事件处理结果
		 
		异常:
		  无
		"""
		event_name = event.getHeader("Event-Name")

		if event_name in ['CHANNEL_CREATE']:
			return self.__channel_create(event)
		elif event_name in ['CHANNEL_ANSWER']:
			return self.__channel_answer(event) 
		elif event_name in ['CHANNEL_HANGUP']:
			return self.__channel_hangup(event) 
		pass

	def __call_time(self, t):
		"""
		格式化呼叫时间
		 
		参数:
		  t - 时间
		返回值:
		  格式化之后的时间
		 
		异常:
		  无
		"""
		return t.replace('-', '').replace(' ', '').replace(':', '') if t else None

	def __channel_create(self, event):
		"""
		呼叫开始事件处理
		 
		参数:
		  event - 事件
		返回值:
		  无
		 
		异常:
		  无
		"""
		if self.__debug:
			#print(event.getHeader("unique-id"), event.getHeader("Caller-Caller-ID-Number"), event.getHeader("Caller-Destination-Number"), event.getHeader("Caller-Callee-ID-Number"))
			pass
		uuid = event.getHeader("unique-id")
		call_dir = event.getHeader("Caller-Direction")

		# inbound侧的呼叫
		if call_dir in ['inbound']:
			caller_num = event.getHeader("Caller-Caller-ID-Number")
			callee_num = event.getHeader("Caller-Destination-Number")
			
			# 判断主、被叫号码是否在监听列表中
			if (caller_num in self.__monitor_numbers or callee_num in self.__monitor_numbers) and uuid not in self.__call:
				session_id = event.getHeader("variable_session_id")

				self.__call[uuid] = {
					"call":True, 
					"caller_num":caller_num, 
					"callee_num":callee_num,
					"direction":call_dir, 
					"call_time":self.__call_time(event.getHeader("Event-Date-Local")),
					"id": session_id
					}
				if self.__debug:
					print("\n%s [begin]" % (session_id))
				print("%s locked the number. caller:%s callee:%s" % (session_id, caller_num, callee_num))

		# outbound侧的呼叫
		elif call_dir in ['outbound']:
			uuid_other = event.getHeader("Other-Leg-Unique-ID")

			# 判断outbound的other_uuid即inbound的uuid是否存在于呼叫中，存在则认为此路是inbound侧相关的呼叫
			if uuid_other in self.__call and uuid not in self.__call:
				caller_num = event.getHeader("Caller-Caller-ID-Number")
				callee_num = event.getHeader("Caller-Callee-ID-Number")

				self.__call[uuid] = {
					"call":True, 
					"caller_num":caller_num, 
					"callee_num":callee_num,
					"direction":call_dir, 
					"call_time":self.__call_time(event.getHeader("Event-Date-Local")),
					"id": self.__call.get(uuid_other, {}).get("id", "0"), 
					"uuid_other": uuid_other if uuid_other else ""}

				info_other = self.__call.get(uuid_other, {})
				if info_other:
					info_other["uuid_other"] = uuid

				if self.__debug:
					print("%s associated the number. caller:%s callee:%s" % (self.__call[uuid]["id"], caller_num, callee_num))

	def __channel_answer(self, event):
		"""
		呼叫接听事件处理
		 
		参数:
		  event - 事件
		返回值:
		  无
		 
		异常:
		  无
		"""
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

		# 抓的pcap包命名规则：[会话ID]_[主叫号码]_[被叫号码]_[呼叫方向]_[呼叫时间].pcap
		pcap_name = "_".join([call.get("id", "0"), 
			call.get("caller_num", ""), 
			call.get("callee_num", ""), 
			call.get("direction", ""), 
			call.get("call_time", "")]) + ".pcap"

		# 这里会创建子进程
		pcap = tcpdump(self.__protocol, self.__eth, os.path.join(self.__path, pcap_name), int(local_media_port), debug=self.__debug)
		if pcap.run():
			print("%s tcpdump begin %s on %s port(src&dst) %s" % (call.get("id", "0"), pcap_name, self.__eth, local_media_port))
			call["pcap"] = pcap
			call["pcap_name"] = pcap_name
		else:
			if self.__debug:
				print("%s tcpdump failed %s on %s port(src&dst) %s" % (call.get("id", "0"), pcap_name, self.__eth, local_media_port))
			pass

	def __channel_hangup(self, event):
		"""
		呼叫挂断事件处理
		 
		参数:
		  event - 事件
		返回值:
		  无
		 
		异常:
		  无
		"""
		uuid = event.getHeader("unique-id")

		call = self.__call.get(uuid, None)
		if not call:
			return 

		pcap = call.get("pcap", None)
		if pcap:
			pcap.terminate()
			print("%s tcpdump end %s" % (call.get("id", "0"), call.get("pcap_name", "")))
			
		
		if self.__debug and not self.__call.get(call.get("uuid_other", ""), {}):
			print("%s [end]\n" % (call.get("id", "0")))

		del self.__call[uuid]
