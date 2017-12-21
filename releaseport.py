# -*- coding: utf-8 -*-
import os

from wox import Wox


class ReleasePort(Wox):
    # 查到端口对应的pid
    FINDPID = 'netstat -aon'  # 查找端口的pid
    FIND_BYSTR = 'netstat -aon|findstr '
    FIND_INFOR_BYPID = "tasklist|findstr "  # 获取pid的信息
    KILLPID_BYSTR = 'taskkill -F -PID '  # 杀死pid

    def findPID(self, port):
        pidSet = set()  # 用于存放pid
        result = os.popen(self.FIND_BYSTR + port)
        res = result.read()
        for line in res.splitlines():
            if line.find("TCP") > 0 or line.find("UDP") > 0:
                pidSet.add(line[::-1].split(" ", 1)[0][::-1])
        return pidSet
        
    def findInforByPid(self, pid):
        if len(pid)>0:
            result = os.popen(self.FIND_INFOR_BYPID + pid)
            res = result.read()
            for line in res.splitlines():
	            if len(line.strip()) > 0:
	            	return line.strip()
        return ""
    def killPID(self, pid):
        if len(pid) > 0 and pid.isdigit():
            result = os.popen(self.KILLPID_BYSTR + pid)
            res = result.read()

    def query(self, port):
        results = []
        pidSet = self.findPID(port)
        result = [{
            'Title':  self.findInforByPid(pid),
            'SubTitle': "进程 " + pid,
            "IcoPath": "Images/app.ico",
            'JsonRPCAction': {
                'method': 'killPID',
                'parameters': [pid]
            }
        } for pid in pidSet]
        if len(pidSet)==0 and len(port) > 0:
            result.append({
                'Title': port+" 空闲",
                'SubTitle': "无进程占用",
                'IcoPath': os.path.join('img', 'letscorp.png')
            })
        return result

if __name__ == "__main__":
    ReleasePort() 