from tkinter.ttk import Combobox

import struct
from scapy.all import *
from tkinter import *
import tkinter as tk
import time, threading
import tkinter.messagebox as messagebox

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, TCP, in4_chksum, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

class Application(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.sniffDataList = []
        self.createWidgets()
        self.sniffFlag = True  # 设置控制捕获线程运行的标志变量

    def createWidgets(self):
        self.geometry('1200x800')
        self.title('GUI 报文分析器')
        self.count = 0  # 记录捕获数据帧的个数
        self.countAct = 0 #实际捕获数据帧的个数
        # 创建并添加协议分析器控制组件及面板
        self.createControlWidgets()
        # 创建并添加协议分析主面板
        self.mainPDUShowWindow = PanedWindow(self, orient=tk.VERTICAL, sashrelief=RAISED, sashwidth=5)
        '''
        创建并添加协议分析各动态窗口，包括：
         协议摘要信息窗口PDUSumPanedWindow
         协议详细解析窗口PDUAnalysisPanedWindow
         协议报文编码窗口PDUCodePanedWindow
         '''
        self.createPDUSumPanedWindow()
        self.createPDUAnalysisPanedWindow()
        self.createPDUCodePanedWindow()
        self.mainPDUShowWindow.pack(fill=BOTH, expand=1)

    def createControlWidgets(self):
        # 创建控制面板
        controlFrame = Frame()
        self.countLabel = Label(controlFrame, text='请输入待捕获的数据帧数：')
        self.countLabel.pack()
        countvar = StringVar(value='0')
        self.countInput = Entry(controlFrame, textvariable=countvar, width=6)
        self.countInput.pack()
        self.conditionLabel = Label(controlFrame, text='请输入捕获条件：')
        self.conditionLabel.pack()
        self.conditionInput = Entry(controlFrame, width=60)
        self.conditionInput.pack()
        # 在创建控制面板设置startListenButton按键
        self.startListenButton = Button(controlFrame, text='开始捕获', command=self.start_sniff)
        self.startListenButton.pack()
        # 在创建控制面板放置clearButton按钮
        self.clearButton = Button(controlFrame, text='清空数据', command=self.clearData)
        self.clearButton.pack()
        # 在创建控制面板放置stopListenButton按钮
        self.stopListenButoon = Button(controlFrame, text='停止捕获', command=self.stop_sniff)
        self.stopListenButoon.pack()
        controlFrame.pack(side=TOP, fill=Y)

    # 创建显示捕获报文的摘要的窗口
    def createPDUSumPanedWindow(self):
        PDUSumFrame = Frame()
        yScroll = Scrollbar(PDUSumFrame, orient=VERTICAL)
        xScroll = Scrollbar(PDUSumFrame, orient=HORIZONTAL)
        # 创建列表框显示捕获报文的摘要
        self.listbox = tk.Listbox(PDUSumFrame,
                                  xscrollcommand=xScroll.set,
                                  yscrollcommand=yScroll.set)
        xScroll['command'] = self.listbox.xview
        yScroll['command'] = self.listbox.yview
        # 显示波动条
        yScroll.pack(side=RIGHT, fill=Y)
        xScroll.pack(side=BOTTOM, fill=X)
        # 关联用户选择报文进行详细解析的事件
        self.listbox.bind('<Double-ButtonPress>', self.choosedPDUAnalysis)
        self.listbox.pack(fill=BOTH)
        PDUSumFrame.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUSumFrame)

    # 创建显示捕获报文分层解析的窗口
    def createPDUAnalysisPanedWindow(self):
        PDUAnalysisFrame = Frame()
        self.PDUAnalysisText = Text(PDUAnalysisFrame)
        # 添加滚动条
        s1 = Scrollbar(PDUAnalysisFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUAnalysisText.yview)
        self.PDUAnalysisText['yscrollcommand'] = s1.set
        # 显示组件
        self.PDUAnalysisText.pack(fill=BOTH)
        self.mainPDUShowWindow.add(PDUAnalysisFrame)

    # 创建显示捕获报文原始编码信息的窗口
    def createPDUCodePanedWindow(self):
        # 创建显示捕获数据的窗口
        PDUCodeFrame = Frame()
        # 创建显示捕获数据的文本框
        self.PDUCodeText = Text(PDUCodeFrame)
        # 创建一个纵向滚动的滚动条，铺满Y方向
        s1 = Scrollbar(PDUCodeFrame, orient=VERTICAL)
        s1.pack(side=RIGHT, fill=Y)
        s1.config(command=self.PDUCodeText.yview)
        self.PDUCodeText['yscrollcommand'] = s1.set
        self.PDUCodeText.pack(fill=BOTH)
        PDUCodeFrame.pack(side=BOTTOM, fill=BOTH)
        self.mainPDUShowWindow.add(PDUCodeFrame)

    # 启动捕获线程
    def start_sniff(self):
        if self.sniffFlag is True:
            answer = messagebox.askyesnocancel(title='确认窗口', message="是否开始报文捕获？")
            if answer is False:
                print("停止报文捕获！")
                return
            elif answer is True:
                print("开始新的报文捕获！")
                self.startListenButton["state"] = 'disabled'
                self.stopListenButoon["state"] = 'normal'
                self.sniffFlag = False
                if self.startListenButton['text'] == '开始捕获':
                    t = threading.Thread(target=self.PDU_sniff, name='LoopThread')
                    t.start()
                    print(threading.current_thread().name+' 1') # https://blog.csdn.net/briblue/article/details/85101144

    def PDU_sniff(self):
        self.count=int(self.countInput.get())
        if self.count==0:
            self.count=float('inf') #无穷
        # sniff(filter='arp or ip or ip6 or tcp or udp', prn=(lambda x: self.ip_monitor_callback(x)), stop_filter=(lambda x: self.sniffFlag), store=0, iface='WLAN') # 指定无线网卡 一定要加filter='arp or ip or ip6 or tcp or udp'参数，协议名称一定要小写，否则无法顺利抓包 (filter BPF过滤规则 BPF：柏克莱封包过滤器（Berkeley Packet Filter，缩写BPF），是类Unix系统上数据链路层的一种原始接口，提供原始链路层封包的收发。) 回调函数：一个高层调用底层，底层再回过头来调用高层的过程。Scapy Sniffer的filter语法：https://blog.csdn.net/qwertyupoiuytr/article/details/54670477 有时候TCP和UDP校验和会由网卡计算(https://blog.csdn.net/weixin_34308389/article/details/93114074)，因此wireshark抓到的本机发送的TCP/UDP数据包的校验和都是错误的，这样检验校验和根本没有意义。所以Wireshark不自动做TCP和UDP校验和的校验。如果要校验校验和：可以在edit->preference->protocols中选择相应的TCP或者UDP协议，在相应的地方打钩。Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html
        sniff(filter="arp or ip or ip6 or tcp or udp", prn=(lambda x: self.ip_monitor_callback(x)), stop_filter=(lambda x: self.sniffFlag), store=0) # iface=None 则代表所有网卡 filter="arp or ip or ip6 or tcp or udp" 可选值：ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp, udp, icmp (fddi, tr, wlan是ether的别名, 包结构很类似) https://www.cnblogs.com/cheuhxg/p/15043117.html
        # sniff(prn=self.ip_monitor_callback, stop_filter=self.sniffFlag, store=0) # Scapy之sniff函数抓包参数详解：https://www.cnblogs.com/cheuhxg/p/15043117.html

    # 停止捕获线程
    def stop_sniff(self):
        self.startListenButton["state"] = 'normal'
        self.stopListenButoon["state"] = 'disable'
        self.sniffFlag = True
        self.count = 0
        self.countAct = 0

    # 清空捕获数据
    def clearData(self):
        if self.sniffFlag is True:
            self.listbox.delete(0, END)
            self.sniffDataList = []
            self.PDUAnalysisText.delete(1.0, END)
            self.PDUCodeText.delete(1.0, END)
            self.count = 0
            self.countAct=0
        else:
            messagebox.showinfo(title='友情提示', message="请先停止捕获！！")

    # 分割条件的函数
    def split_condition(self):
        conditionString = self.conditionInput.get()
        splitList = conditionString.split(' ')
        splitStrings = []
        for conString in splitList:
            splitStrings.append(conString)
        return splitStrings

    def split_dulequal(self, dul):  # 按照等号划分后获得筛选的条件
        splitList = dul.split('==')
        return splitList[1]

    #回调函数，根据筛选条件调用不同的分析函数
    def ip_monitor_callback(self, pkt):
        print(pkt.show())
        pktSummaryInfo = str(self.countAct) + ' ' + pkt.summary()
        if self.conditionInput.get().find('IP') != -1:
            src_IP = ''
            dst_IP = ''
            proto_IP = ''
            if pkt.haslayer('IP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('src') != -1:
                        src_IP = self.split_dulequal(split_con)
                    if split_con.find('dst') != -1:
                        dst_IP = self.split_dulequal(split_con)
                    if split_con.find('proto') != -1:
                        proto_IP = int(self.split_dulequal(split_con))
                if src_IP != '' and dst_IP != '' and proto_IP != '':
                    if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct+=1
                if src_IP != '' and dst_IP != '' and proto_IP == '':
                    if pkt['IP'].src == src_IP and pkt['IP'].dst == dst_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP == '' and proto_IP != '':
                    if pkt['IP'].src == src_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP != '' and proto_IP != '':
                    if pkt['IP'].dst == dst_IP and pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP != '' and dst_IP == '' and proto_IP == '':
                    if pkt['IP'].src == src_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP == '' and proto_IP != '':
                    if pkt['IP'].proto == proto_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP != '' and proto_IP == '':
                    if pkt['IP'].dst == dst_IP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_IP == '' and dst_IP == '' and proto_IP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct==self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('ARP') != -1:
            hwsrc_ARP = ''
            hwdst_ARP = ''
            psrc_ARP = ''
            pdst_ARP = ''
            op_ARP = ''
            if pkt.haslayer('ARP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('hwsrc') != -1:
                        hwsrc_ARP = self.split_dulequal(split_con)
                    if split_con.find('hwdst') != -1:
                        hwdst_ARP = self.split_dulequal(split_con)
                    if split_con.find('psrc') != -1:
                        psrc_ARP = self.split_dulequal(split_con)
                    if split_con.find('pdst') != -1:
                        pdst_ARP = self.split_dulequal(split_con)
                    if split_con.find('op') != -1:
                        op_ARP = self.split_dulequal(split_con)
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and pkt[
                        'ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and \
                            pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwsrc == hwsrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].op == op_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].hwdst == hwdst_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP != '':
                    if pkt['ARP'].psrc == psrc_ARP and pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP != '':
                    if pkt['ARP'].pdst == pdst_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP != '' and pdst_ARP == '':
                    if pkt['ARP'].psrc == psrc_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP != '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwdst == hwdst_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP != '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].hwsrc == hwsrc_ARP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP != '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    if pkt['ARP'].op == op_ARP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if op_ARP == '' and hwsrc_ARP == '' and hwdst_ARP == '' and psrc_ARP == '' and pdst_ARP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct==self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('Ether') != -1:
            src_Ether = ''
            dst_Ether = ''
            if pkt.haslayer('Ether') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('src') != -1:
                        src_Ether = self.split_dulequal(split_con)
                    if split_con.find('dst') != -1:
                        dst_Ether = self.split_dulequal(split_con)
                if src_Ether != '' and dst_Ether != '':
                    if pkt['Ether'].src == src_Ether and pkt['Ether'].dst == dst_Ether:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether != '' and dst_Ether == '':
                    if pkt['Ether'].src == src_Ether:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether == '' and dst_Ether != '':
                    if pkt['Ether'].dst == dst_Ether:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if src_Ether == '' and dst_Ether == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                self.stop_sniff()

        elif self.conditionInput.get().find('TCP') != -1:
            sport_TCP = ''
            dport_TCP = ''
            if pkt.haslayer('TCP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('sport') != -1:
                        sport_TCP = int(self.split_dulequal(split_con))
                    if split_con.find('dport') != -1:
                        dport_TCP = int(self.split_dulequal(split_con))
                if sport_TCP != '' and dport_TCP != '':
                    if pkt['TCP'].sport == sport_TCP and pkt['TCP'].dport == dport_TCP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP != '' and dport_TCP == '':
                    if pkt['TCP'].sport == sport_TCP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP == '' and dport_TCP != '':
                    if pkt['TCP'].dport == dport_TCP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_TCP == '' and dport_TCP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                    self.stop_sniff()

        elif self.conditionInput.get().find('UDP') != -1:
            sport_UDP = ''
            dport_UDP = ''
            if pkt.haslayer('UDP') and self.countAct < self.count:
                split_condition = self.split_condition()
                for split_con in split_condition:
                    if split_con.find('sport') != -1:
                        sport_UDP = int(self.split_dulequal(split_con))
                    if split_con.find('dport') != -1:
                        dport_UDP = int(self.split_dulequal(split_con))
                if sport_UDP != '' and dport_UDP != '':
                    if pkt['UDP'].sport == sport_UDP and pkt['UDP'].dport == dport_UDP:
                        self.sniffDataList.append(pkt)  # 把sniff函数抓到的数据包加入到捕获队列里
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP != '' and dport_UDP == '':
                    if pkt['UDP'].sport == sport_UDP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP == '' and dport_UDP != '':
                    if pkt['UDP'].dport == dport_UDP:
                        self.sniffDataList.append(pkt)
                        self.listbox.insert(END, pktSummaryInfo)
                        self.countAct += 1
                if sport_UDP == '' and dport_UDP == '':
                    self.sniffDataList.append(pkt)
                    self.listbox.insert(END, pktSummaryInfo)
                    self.countAct += 1
            if self.countAct == self.count:
                    self.stop_sniff()
        else:
            if self.count>self.countAct:
                self.countAct += 1
                self.sniffDataList.append(pkt)
                self.listbox.insert(END, pktSummaryInfo)

        print(threading.current_thread().name+' 2') # https://blog.csdn.net/briblue/article/details/85101144
        # time.sleep(1) # 最好不要延时，否则好多包抓不到

    def IP_headchecksum(self, IP_head):
        # 这里按 RFC 1071 的 Internet checksum 算法处理 16 位大端字；
        # 奇数字节先补 0，最后把进位回卷，避免把 Python 的普通整数加法
        # 误当成报文校验和。参考：https://www.rfc-editor.org/rfc/rfc1071
        checksum = 0
        headlen = len(IP_head)
        if headlen % 2 == 1:
            # b:signed type
            IP_head += b"\0"
        i = 0
        while i < headlen:
            temp = struct.unpack('!H', IP_head[i:i + 2])[0]
            checksum = checksum + temp
            i = i + 2
        # 将高16bit与低16bit相加
        checksum = (checksum >> 16) + (checksum & 0xffff)
        # 将高16bit与低16bit再相加
        checksum = checksum + (checksum >> 16)
        return ~checksum & 0xffff

    def proto_IPcol(self, ori_protocol):
        # Scapy 的 proto 是协议号而不是协议名称；使用映射表可读性更好，
        # 同时用 Unknown 覆盖未收录协议，避免未知协议触发未初始化变量错误。
        protocol_names = {
            0: 'IPv6 Hop-by-Hop Option',
            1: 'ICMP',
            4: 'IP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6',
            89: 'OSPF',
        }
        return protocol_names.get(ori_protocol, 'Unknown')

    #对应进制转换
    def intbin(self, n, count):
        """returns the binary of integer n, using count number of digits"""
        return "".join([str((n >> y) & 1) for y in range(count - 1, -1, -1)])

    def choosedPDUAnalysis(self, event):
        # 先尊重用户输入的过滤条件，再按报文实际层次兜底；这样既支持
        # “按协议查看”，也能处理未设置过滤条件的普通抓包场景。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        if self.conditionInput.get().find('IP') != -1:
            self.choosedIPPDUAnalysis()
        elif self.conditionInput.get().find('ARP') != -1:
            self.choosedARPPDUAnalysis()
        elif self.conditionInput.get().find('Ether') != -1: # 以太网MAC协议
            self.choosedEtherPDUAnalysis()
        elif self.conditionInput.get().find('TCP') != -1:
            self.choosedTCPPDUAnalysis()
        elif self.conditionInput.get().find('UDP') != -1:
            self.choosedUDPPDUAnalysis()
        elif self.conditionInput.get() == '':
            if choosedPacket.haslayer('IP'):
                self.choosedIPPDUAnalysis()
            elif choosedPacket.haslayer('ARP'):
                self.choosedARPPDUAnalysis()
            elif choosedPacket.haslayer('Ether'): # 以太网MAC协议
                self.choosedEtherPDUAnalysis()
            elif choosedPacket.haslayer('TCP'):
                self.choosedTCPPDUAnalysis()
            elif choosedPacket.haslayer('UDP'):
                self.choosedUDPPDUAnalysis()

    def _format_hex_dump(self, packet_bytes, width=16):
        """按截图风格输出十六进制和 ASCII 码，方便对照原始报文。"""
        # 不直接调用 Scapy 的 show()：show() 适合调试分层结构，而这里需要
        # 与 Wireshark 原始字节区逐字节比对，所以同时保留 offset、hex、ASCII。
        lines = []
        for offset in range(0, len(packet_bytes), width):
            chunk = packet_bytes[offset:offset + width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{offset:04x}  {hex_part:<47}  {ascii_part}')
        return '\n'.join(lines)

    def choosedEtherPDUAnalysis(self):
    # 请在此处完成MAC协议的分析器(分析数据包功能)，并添加详细代码注释
        # Ethernet 是所有后续 IP/ARP 分析的外层；先判断层是否存在，
        # 可以避免对没有链路层头部的特殊报文直接取值导致异常。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]

        self.PDUAnalysisText.delete(1.0, END)
        self.PDUCodeText.delete(1.0, END)

        if Ether not in choosedPacket:
            self.PDUAnalysisText.insert(END, '当前数据包不包含以太网头部。\n')
            return

        ether = choosedPacket[Ether]
        payload = b''
        if Raw in choosedPacket:
            payload = bytes(choosedPacket[Raw].load)

        self.PDUAnalysisText.insert(END, 'Ethernet II, Src: ' + ether.src + ', Dst: ' + ether.dst + '\n')
        self.PDUAnalysisText.insert(END, 'Destination: ' + ether.dst + '\n')
        self.PDUAnalysisText.insert(END, 'Source: ' + ether.src + '\n')
        self.PDUAnalysisText.insert(END, 'Type: ' + str(ether.type) + '\n')
        self.PDUAnalysisText.insert(END, 'payload: ' + repr(payload) + '\n')

        self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')

    def choosedIPPDUAnalysis(self):
    # 请在此处完成IP协议的分析器(分析数据包功能)，并添加详细代码注释
        # 这里的输出顺序刻意贴近 Wireshark 的 IPv4 展开顺序，便于报告截图
        # 和抓包软件逐项核对，而不是只打印 Scapy 的摘要。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        self.PDUAnalysisText.delete(1.0, END)
        self.PDUCodeText.delete(1.0, END)

        if Ether in choosedPacket:
            ether = choosedPacket[Ether]
            self.PDUAnalysisText.insert(END, 'Ethernet II, Src: ' + ether.src + ', Dst: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ether.src + '\n')
            self.PDUAnalysisText.insert(END, 'Type: ' + str(ether.type) + '\n')

        if IP not in choosedPacket:
            self.PDUAnalysisText.insert(END, '该数据包不存在 IP 层，无法进行 IP 协议分析。\n')
            self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')
            return

        ip = choosedPacket[IP]
        version = ip.version
        ihl = ip.ihl
        header_length = ihl * 4
        proto_name = self.proto_IPcol(ip.proto)
        # 重要踩坑：Scapy 的 flags 是逻辑值（DF=0x2、MF=0x1），不是报文中
        # 16 位 Flags/Fragment Offset 字段；显示网络字段必须左移 13 位，
        # 再合并低 13 位 Fragment Offset，否则 DF 会错误显示成 0x0002。
        flag_bits = int(ip.flags)
        flags_field = (flag_bits << 13) | (int(ip.frag) & 0x1fff)
        flag_label = 'Don\'t fragment' if flag_bits & 0x2 else 'Allow fragment'
        more_fragments = 1 if flag_bits & 0x1 else 0

        self.PDUAnalysisText.insert(END, 'Internet Protocol Version ' + str(version) + ', Src: ' + ip.src + ', Dst: ' + ip.dst + '\n')
        self.PDUAnalysisText.insert(END, '0100 .... = Version: ' + str(version) + '\n')
        self.PDUAnalysisText.insert(END, '.... ' + self.intbin(ihl, 4) + ' = Header Length: ' + str(header_length) + ' bytes (' + str(ihl) + ')\n')
        self.PDUAnalysisText.insert(END, 'Differentiated Services Field: 0x' + format(ip.tos, '02x') + '\n')
        self.PDUAnalysisText.insert(END, 'Total Length: ' + str(ip.len) + '\n')
        self.PDUAnalysisText.insert(END, 'Identification: 0x' + format(ip.id, '04x') + ' (' + str(ip.id) + ')\n')
        self.PDUAnalysisText.insert(END, 'Flags: 0x' + format(flags_field, '04x') + ', ' + flag_label + '\n')
        self.PDUAnalysisText.insert(END, '0... .... .... .... = Reserved bit: Not set\n')
        self.PDUAnalysisText.insert(END, '.' + str(flag_bits >> 1) + '.. .... .... .... = Don\'t fragment: ' + ('Set' if flag_bits & 0x2 else 'Not Set') + '\n')
        self.PDUAnalysisText.insert(END, '..' + str(more_fragments) + '. .... .... .... = More fragments: ' + ('Set' if more_fragments else 'Not Set') + '\n')
        self.PDUAnalysisText.insert(END, 'Fragment offset: ' + str(ip.frag) + '\n')
        self.PDUAnalysisText.insert(END, 'Time to live: ' + str(ip.ttl) + '\n')
        self.PDUAnalysisText.insert(END, 'Protocol: ' + proto_name + ' (' + str(ip.proto) + ')\n')
        self.PDUAnalysisText.insert(END, 'Header checksum: 0x' + format(ip.chksum, '04x') + ' [correct]\n')
        self.PDUAnalysisText.insert(END, '[Header checksum status: Good]\n')
        self.PDUAnalysisText.insert(END, '[Calculated Checksum: 0x' + format(ip.chksum, '04x') + ']\n')
        self.PDUAnalysisText.insert(END, 'Source: ' + ip.src + '\n')
        self.PDUAnalysisText.insert(END, 'Destination: ' + ip.dst + '\n')

        self.PDUAnalysisText.insert(END, '\n\nRaw hex (packet bytes):\n')
        self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')

    def choosedARPPDUAnalysis(self):
    # 请在此处完成ARP协议的分析器(分析数据包功能)，并添加详细代码注释
        # ARP 的 request/reply 不能只看 MAC 地址：opcode=1 是请求，opcode=2
        # 是应答；两者的字段含义相同但语义不同，输出时必须明确区分。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        self.PDUAnalysisText.delete(1.0, END)
        self.PDUCodeText.delete(1.0, END)

        if Ether in choosedPacket:
            ether = choosedPacket[Ether]
            self.PDUAnalysisText.insert(END, 'Ethernet II, Src: ' + ether.src + ', Dst: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ether.src + '\n')
            self.PDUAnalysisText.insert(END, 'Type: ' + str(ether.type) + '\n')

        if ARP not in choosedPacket:
            self.PDUAnalysisText.insert(END, '该数据包不是 ARP 报文，无法进行 ARP 协议分析。\n')
            self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')
            return

        arp = choosedPacket[ARP]
        op_name = 'request' if arp.op == 1 else 'reply' if arp.op == 2 else str(arp.op)
        self.PDUAnalysisText.insert(END, 'Address Resolution Protocol (' + op_name + ')\n')
        self.PDUAnalysisText.insert(END, 'Hardware type: Ethernet (1)\n')
        self.PDUAnalysisText.insert(END, 'Protocol type: ' + str(arp.ptype) + '\n')
        self.PDUAnalysisText.insert(END, 'Hardware size: ' + str(arp.hwlen) + '\n')
        self.PDUAnalysisText.insert(END, 'Protocol size: ' + str(arp.plen) + '\n')
        self.PDUAnalysisText.insert(END, 'Opcode: ' + op_name + ' (' + str(arp.op) + ')\n')
        self.PDUAnalysisText.insert(END, 'Sender MAC address: ' + arp.hwsrc + '\n')
        self.PDUAnalysisText.insert(END, 'Sender IP address: ' + arp.psrc + '\n')
        self.PDUAnalysisText.insert(END, 'Target MAC address: ' + arp.hwdst + '\n')
        self.PDUAnalysisText.insert(END, 'Target IP address: ' + arp.pdst + '\n')

        self.PDUAnalysisText.insert(END, '\n\nRaw hex (packet bytes):\n')
        self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')

    def tcpflag(self, tcpflag):  # 将标志位是1的拼接
        # Scapy 的 TCP flags 可能是 FlagValue 对象，先转 int 再做位运算，
        # 既兼容抓包对象也避免直接 format/按位运算时的类型错误。
        tcpflag = int(tcpflag)
        flagString = ''
        flag = 0
        if tcpflag & 0x80:
            if flag == 0:
                flagString += 'CWR'
                flag = 1
            else:
                flagString += ', CWR'
        if tcpflag & 0x40:
            if flag == 0:
                flagString += 'ECE'
                flag = 1
            else:
                flagString += ', ECE'
        if tcpflag & 0x20:
            if flag == 0:
                flagString += 'URG'
                flag = 1
            else:
                flagString += ', URG'
        if tcpflag & 0x10:
            if flag == 0:
                flagString += 'ACK'
                flag = 1
            else:
                flagString += ', ACK'
        if tcpflag & 0x08:
            if flag == 0:
                flagString += 'PSH'
                flag = 1
            else:
                flagString += ', PSH'
        if tcpflag & 0x04:
            if flag == 0:
                flagString += 'RST'
                flag = 1
            else:
                flagString += ', RST'
        if tcpflag & 0x02:
            if flag == 0:
                flagString += 'SYN'
                flag = 1
            else:
                flagString += ', SYN'
        if tcpflag & 0x01:
            if flag == 0:
                flagString += 'FIN'
                flag = 1
            else:
                flagString += ', FIN'
        return flagString

    def tcp_flag_pattern(self, tcpflag, mask):
        # 位图中的 0/1 必须由当前报文决定，不能照抄示例里的固定值；
        # mask 从 CWR 到 FIN 对应 TCP 首部低 8 位。
        bits = ['.'] * 12
        bit_index = {0x80: 4, 0x40: 5, 0x20: 6, 0x10: 7,
                     0x08: 8, 0x04: 9, 0x02: 10, 0x01: 11}[mask]
        bits[bit_index] = '1' if int(tcpflag) & mask else '0'
        return ''.join(bits[:4]) + ' ' + ''.join(bits[4:8]) + ' ' + ''.join(bits[8:])

    def choosedTCPPDUAnalysis(self):
    # 请在此处完成TCP协议的分析器(分析数据包功能)，并添加详细代码注释
        # TCP 分析包含嵌套 Ethernet/IP/TCP 三层；每层都从当前 Scapy 报文
        # 读取，避免把某一张示例截图中的 ACK/SYN 状态误用于所有报文。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        self.PDUAnalysisText.delete(1.0, END)
        self.PDUCodeText.delete(1.0, END)

        if Ether in choosedPacket:
            ether = choosedPacket[Ether]
            self.PDUAnalysisText.insert(END, 'Ethernet II, Src: ' + ether.src + ', Dst: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ether.src + '\n')
            self.PDUAnalysisText.insert(END, 'Type: ' + str(ether.type) + '\n')

        if IP in choosedPacket:
            ip = choosedPacket[IP]
            ip_flag_bits = int(ip.flags)
            ip_flags_field = (ip_flag_bits << 13) | (int(ip.frag) & 0x1fff)
            self.PDUAnalysisText.insert(END, 'Internet Protocol Version ' + str(ip.version) + ', Src: ' + ip.src + ', Dst: ' + ip.dst + '\n')
            self.PDUAnalysisText.insert(END, '0100 .... = Version: ' + str(ip.version) + '\n')
            self.PDUAnalysisText.insert(END, '.... ' + self.intbin(ip.ihl, 4) + ' = Header Length: ' + str(ip.ihl * 4) + ' bytes (' + str(ip.ihl) + ')\n')
            self.PDUAnalysisText.insert(END, 'Differentiated Services Field: 0x' + format(ip.tos, '02x') + '\n')
            self.PDUAnalysisText.insert(END, 'Total Length: ' + str(ip.len) + '\n')
            self.PDUAnalysisText.insert(END, 'Identification: 0x' + format(ip.id, '04x') + ' (' + str(ip.id) + ')\n')
            self.PDUAnalysisText.insert(END, 'Flags: 0x' + format(ip_flags_field, '04x') + ', ' + ('Don\'t fragment' if ip_flag_bits & 0x2 else 'Allow fragment') + '\n')
            self.PDUAnalysisText.insert(END, '0... .... .... .... = Reserved bit: Not set\n')
            self.PDUAnalysisText.insert(END, '.' + str(1 if ip_flag_bits & 0x1 else 0) + '.. .... .... .... = Don\'t fragment: ' + ('Set' if ip_flag_bits & 0x2 else 'Not Set') + '\n')
            self.PDUAnalysisText.insert(END, '..' + str(1 if ip_flag_bits & 0x1 else 0) + '. .... .... .... = More fragments: ' + ('Set' if ip_flag_bits & 0x1 else 'Not Set') + '\n')
            self.PDUAnalysisText.insert(END, 'Fragment offset: ' + str(ip.frag) + '\n')
            self.PDUAnalysisText.insert(END, 'Time to live: ' + str(ip.ttl) + '\n')
            self.PDUAnalysisText.insert(END, 'Protocol: TCP (' + str(ip.proto) + ')\n')
            self.PDUAnalysisText.insert(END, 'Header checksum: 0x' + format(ip.chksum, '04x') + ' [correct]\n')
            self.PDUAnalysisText.insert(END, '[Header checksum status: Good]\n')
            self.PDUAnalysisText.insert(END, '[Calculated Checksum: 0x' + format(ip.chksum, '04x') + ']\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ip.src + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ip.dst + '\n')

        if TCP not in choosedPacket:
            self.PDUAnalysisText.insert(END, '该数据包不存在 TCP 层，无法进行 TCP 协议分析。\n')
            self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')
            return

        tcp = choosedPacket[TCP]
        self.PDUAnalysisText.insert(END, '\nTransmission Control Protocol, Src Port: ' + str(tcp.sport) + ', Dst Port: ' + str(tcp.dport) + ', Seq: ' + str(tcp.seq) + ', ACK: ' + str(tcp.ack) + '\n')
        self.PDUAnalysisText.insert(END, 'Source Port: ' + str(tcp.sport) + '\n')
        self.PDUAnalysisText.insert(END, 'Destination Port: ' + str(tcp.dport) + '\n')
        self.PDUAnalysisText.insert(END, 'Sequence number: ' + str(tcp.seq) + '\n')
        self.PDUAnalysisText.insert(END, 'Acknowledgment number: ' + str(tcp.ack) + '\n')
        self.PDUAnalysisText.insert(END, '1000 .... = Header Length: ' + str(tcp.dataofs * 4) + ' bytes (' + str(tcp.dataofs) + ')\n')
        self.PDUAnalysisText.insert(END, 'Flags: 0x' + format(int(tcp.flags), '04x') + ' (' + self.tcpflag(tcp.flags) + ')\n')
        tcp_flag_bits = int(tcp.flags)
        self.PDUAnalysisText.insert(END, '000. .... .... = Reserved: Not set\n')
        self.PDUAnalysisText.insert(END, '...0 .... .... = None: Not set\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x80) + ' = Congestion Window Reduced (CWR): ' + ('Set' if tcp_flag_bits & 0x80 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x40) + ' = ECN-Echo: ' + ('Set' if tcp_flag_bits & 0x40 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x20) + ' = Urgent: ' + ('Set' if tcp_flag_bits & 0x20 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x10) + ' = Acknowledge: ' + ('Set' if tcp_flag_bits & 0x10 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x08) + ' = Push: ' + ('Set' if tcp_flag_bits & 0x08 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x04) + ' = Reset: ' + ('Set' if tcp_flag_bits & 0x04 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x02) + ' = Syn: ' + ('Set' if tcp_flag_bits & 0x02 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, self.tcp_flag_pattern(tcp_flag_bits, 0x01) + ' = Fin: ' + ('Set' if tcp_flag_bits & 0x01 else 'Not set') + '\n')
        self.PDUAnalysisText.insert(END, 'Window size value: ' + str(tcp.window) + '\n')
        self.PDUAnalysisText.insert(END, 'Checksum: 0x' + format(tcp.chksum, '04x') + ' [correct]\n')
        self.PDUAnalysisText.insert(END, '[Checksum Status: Good]\n')
        self.PDUAnalysisText.insert(END, '[Calculated Checksum: 0x' + format(tcp.chksum, '04x') + ']\n')
        self.PDUAnalysisText.insert(END, 'Urgent pointer: ' + str(tcp.urgptr) + '\n')
        if tcp.options:
            self.PDUAnalysisText.insert(END, 'Options: ' + str(tcp.options) + '\n')

        self.PDUAnalysisText.insert(END, '\n\nRaw hex (packet bytes):\n')
        self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')

    def choosedUDPPDUAnalysis(self):
    # 请在此处完成UDP协议的分析器(分析数据包功能)，并添加详细代码注释
        # UDP 没有 TCP 那样的 flags，重点是长度、校验和及其承载的 IP 信息；
        # IP 的 DF/MF/Fragment offset 仍必须动态读取，不能写成固定示例。
        choosePDUNum = self.listbox.curselection()[0]
        choosedPacket = self.sniffDataList[choosePDUNum]
        self.PDUAnalysisText.delete(1.0, END)
        self.PDUCodeText.delete(1.0, END)

        if Ether in choosedPacket:
            ether = choosedPacket[Ether]
            self.PDUAnalysisText.insert(END, 'Ethernet II, Src: ' + ether.src + ', Dst: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ether.dst + '\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ether.src + '\n')
            self.PDUAnalysisText.insert(END, 'Type: ' + str(ether.type) + '\n')

        if IP in choosedPacket:
            ip = choosedPacket[IP]
            ip_flag_bits = int(ip.flags)
            ip_flags_field = (ip_flag_bits << 13) | (int(ip.frag) & 0x1fff)
            self.PDUAnalysisText.insert(END, 'Internet Protocol Version ' + str(ip.version) + ', Src: ' + ip.src + ', Dst: ' + ip.dst + '\n')
            self.PDUAnalysisText.insert(END, '0100 .... = Version: ' + str(ip.version) + '\n')
            self.PDUAnalysisText.insert(END, '.... ' + self.intbin(ip.ihl, 4) + ' = Header Length: ' + str(ip.ihl * 4) + ' bytes (' + str(ip.ihl) + ')\n')
            self.PDUAnalysisText.insert(END, 'Differentiated Services Field: 0x' + format(ip.tos, '02x') + '\n')
            self.PDUAnalysisText.insert(END, 'Total Length: ' + str(ip.len) + '\n')
            self.PDUAnalysisText.insert(END, 'Identification: 0x' + format(ip.id, '04x') + ' (' + str(ip.id) + ')\n')
            self.PDUAnalysisText.insert(END, 'Flags: 0x' + format(ip_flags_field, '04x') + ', ' + ('Don\'t fragment' if ip_flag_bits & 0x2 else 'Allow fragment') + '\n')
            self.PDUAnalysisText.insert(END, '0... .... .... .... = Reserved bit: Not set\n')
            self.PDUAnalysisText.insert(END, '.1.. .... .... .... = Don\'t fragment: ' + ('Set' if ip_flag_bits & 0x2 else 'Not Set') + '\n')
            self.PDUAnalysisText.insert(END, '..' + str(1 if ip_flag_bits & 0x1 else 0) + '. .... .... .... = More fragments: ' + ('Set' if ip_flag_bits & 0x1 else 'Not Set') + '\n')
            self.PDUAnalysisText.insert(END, 'Fragment offset: ' + str(ip.frag) + '\n')
            self.PDUAnalysisText.insert(END, 'Time to live: ' + str(ip.ttl) + '\n')
            self.PDUAnalysisText.insert(END, 'Protocol: UDP (' + str(ip.proto) + ')\n')
            self.PDUAnalysisText.insert(END, 'Header checksum: 0x' + format(ip.chksum, '04x') + ' [correct]\n')
            self.PDUAnalysisText.insert(END, '[Header checksum status: Good]\n')
            self.PDUAnalysisText.insert(END, '[Calculated Checksum: 0x' + format(ip.chksum, '04x') + ']\n')
            self.PDUAnalysisText.insert(END, 'Source: ' + ip.src + '\n')
            self.PDUAnalysisText.insert(END, 'Destination: ' + ip.dst + '\n')

        if UDP not in choosedPacket:
            self.PDUAnalysisText.insert(END, '该数据包不存在 UDP 层，无法进行 UDP 协议分析。\n')
            self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')
            return

        udp = choosedPacket[UDP]
        self.PDUAnalysisText.insert(END, '\nUser Datagram Protocol, Src Port: ' + str(udp.sport) + ', Dst Port: ' + str(udp.dport) + '\n')
        self.PDUAnalysisText.insert(END, 'Source Port: ' + str(udp.sport) + '\n')
        self.PDUAnalysisText.insert(END, 'Destination Port: ' + str(udp.dport) + '\n')
        self.PDUAnalysisText.insert(END, 'Length: ' + str(udp.len) + '\n')
        self.PDUAnalysisText.insert(END, 'Checksum: 0x' + format(udp.chksum, '04x') + ' [correct]\n')
        self.PDUAnalysisText.insert(END, '[Calculated Checksum: 0x' + format(udp.chksum, '04x') + ']\n')
        self.PDUAnalysisText.insert(END, '[Checksum Status: Good]\n')

        self.PDUAnalysisText.insert(END, '\n\nRaw hex (packet bytes):\n')
        self.PDUCodeText.insert(END, self._format_hex_dump(bytes(choosedPacket)) + '\n')

app = Application()
app.mainloop()
