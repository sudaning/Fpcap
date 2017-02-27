#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
import os
from optparse import OptionParser, OptionGroup
from fpcap import capturePcap

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
		print("no any number will be monitored")
		os.sys.exit(0)
	else:
		print("number monitored list:%s" % num_list)

	p = capturePcap(options.host, options.port, options.password, debug=True)
	p.set_pcap(eth=options.eth).set_numbers(num_list)
	p.run(36000)