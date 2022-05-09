import sys
from PyQt5.QtWidgets import QApplication, QComboBox, QMainWindow, QMessageBox,QCheckBox,QLineEdit,QPlainTextEdit,QTextEdit,QTableWidgetItem,QDialog
from evui import Ui_MainWindow
from aboutdialog import Ui_aboutdialog
from PyQt5.QtCore import QThread, pyqtSignal,QMutex,QUrl
from PyQt5.QtGui import QIntValidator,QDoubleValidator
from PyQt5.QtGui import QDesktopServices
import traceback
import random
import hashlib
from ast import literal_eval
from scapy.all import *
from evilpacket import *

def splitbylength(s,length):
    '''
    split a string by length
    '''
    return [s[i:i+length] for i in range(0, len(s), length)]



class SendThread(QThread):
    statustrigger = pyqtSignal(str)
    qmessagetrigger=pyqtSignal(str)
    receivedpackets=pyqtSignal(str,str,str,str)
    formoptions={}

    def __init__(self,form):
        print('init send thread')
        super(SendThread, self).__init__()
        self.form=form
        #thread connect
        self.statustrigger.connect(self.form.displaystatus)
        self.qmessagetrigger.connect(self.form.displayqmessage)
        self.receivedpackets.connect(self.form.displayreceivedpackets)
        
    
    def showstatus(self,status):
        '''
        show status in main window
        '''
        self.statustrigger.emit(status)

    def processpacket(self,packet):
        '''
        process packet
        '''

        #check src ip and esclude icmp
        if self.getoption('ipaddress')!=packet[IP].src and not packet.haslayer(ICMP):
            # print(f'ip address not match {packet[IP].src} != {self.getoption("ipaddress")}')
            return
        #check sport
        if packet.haslayer(TCP) and self.getoption('sport')!=packet[TCP].dport:
            # print(f'sport not match {packet[TCP].dport} != {self.getoption("sport")}')
            return

        protocol='UNKNOWN'
        flags=''
        payload=''
        ttl=str(packet[IP].ttl)
        #if icmp
        if packet.haslayer(ICMP):
            protocol='ICMP'
        #if tcp
        elif packet[TCP]:
            protocol='TCP'
            flags=str(packet[TCP].flags) 
            payload=str(packet[TCP].payload)
        
        
        self.receivedpackets.emit(protocol,flags,ttl,payload)

    
    def stop(self):
        '''
        stop sniffer and quit
        '''
        if hasattr(self,'sniffer'):
            print('stopping thread listening')
            try:
                self.sniffer.stop()
            except:
                pass
        self.terminate()

    def getoption(self,option):
        '''
        get option
        '''
        if option in self.formoptions:
            return self.formoptions[option]
        else:
            print(f'option:{option} not found')
            return None
        


    def setoption(self,option,value=None):
        '''
        set option with value
        if value in null,automatically extract from forms
        '''
        if value!=None:
            #print(option,value)
            self.formoptions[option]=value
            return 
        try:
            optboj=getattr(self.form,option)
        except:
            print(f'Error:option {option} not found')
            return None
        #if Qcheckbox
        if isinstance(optboj,QCheckBox):
            self.setoption(option,optboj.isChecked())
        #if Qlineedit
        elif isinstance(optboj,QLineEdit):
            self.setoption(option,optboj.text())
        #if Qplaintextedit
        elif isinstance(optboj,QPlainTextEdit) or isinstance(optboj,QTextEdit):
            self.setoption(option,optboj.toPlainText())
        #if Qcombobox
        elif isinstance(optboj,QComboBox):
            self.setoption(option,optboj.currentText())
        else:
            print(f'Error:option {option} type not found whose type is {type(optboj)}')
            return None
        #if int 
        if option in self.form.intforms:
            self.setoption(option,int(self.getoption(option)))
        #if double 
        if option in self.form.doubleforms:
            self.setoption(option,float(self.getoption(option)))
        return self.getoption(option)



    def extractformoptions(self):
        '''
        extract form options and make constrains
        '''
        if self.setoption('randomsport'):
            self.setoption('sport',random.randint(40000,65535))
        elif not  (1<= self.setoption('sport') <= 65535):
            return False,f'sport must be between 1 and 65535'

        if not (1<= self.setoption('dport') <= 65535):
            return False,f'dport must be between 1 and 65535'
        
        if self.setoption('breaktcp'):
            if self.setoption('tcpsegmentby')<=0:
                return False,f'tcpsegmentby must be greater than 0'

        if self.setoption('breakip'):
            if self.setoption('ipfragmentby')<8:
                return False,f'ipfragmentby must be greater than 7'
        
        if self.setoption('fakettl'):
            if not (1<= self.setoption('ttlnum') <= 255):
                return False,f'ttl must be between 1 and 255'        
        try:
            print(literal_eval(self.setoption('tcpoptions')))
            self.setoption('tcpoptions',literal_eval(self.setoption('tcpoptions')))
        except:
            return False,f'tcpoptions must be a valid python list'


        otheroptions=['ipaddress','tcppayload','shuffle','badchecksum','badchecksumtype','fakettltype','sleeptime','httpprotocol','corruptack']
        for option in otheroptions:
            self.setoption(option)
        try:
            self.setoption('ipaddress',socket.gethostbyname(self.getoption('ipaddress')))
        except:
            return False,f'ipaddress {self.getoption("ipaddress")} failed to resolve'

        #http payload format 
        if self.setoption('httpprotocol'):
            self.setoption('tcppayload',self.setoption('tcppayload').strip().replace("\r\n","\n").replace("\n","\r\n")+"\r\n\r\n")
        else:
            self.setoption('tcppayload')
        return True,''

    def sendpackets(self):
        '''
        extract form options and send packets
        '''
        res,errmsg=self.extractformoptions()
        if not res:
            return res,errmsg

        #define vars
        ipaddress=self.getoption('ipaddress')
        sport=self.getoption('sport')
        dport=self.getoption('dport')
        tcpoptions=self.getoption('tcpoptions')
        tcppayload=self.getoption('tcppayload')
        #sniffing
        self.packetsset=set()
        self.snifferlock=QMutex()
        self.sniffer=AsyncSniffer(prn=self.processpacket, store=False, filter=f"host {ipaddress} or icmp")
        self.sniffer.start()
        #establish connection
        self.showstatus("establishing connection...")
        synpacket=IP(dst=ipaddress,id=RandShort())/TCP(sport=sport,dport=dport,flags="S",seq=RandShort()+114514,window=RandShort(),options=tcpoptions)
        receivepacket=sr1(synpacket,timeout=10)
        if not receivepacket:
            return False,'connection failed'
        ackpacket=IP(dst=ipaddress)/TCP(sport=sport,dport=dport,flags="A",ack=receivepacket.seq+1,seq=receivepacket.ack,window=receivepacket.window,options=tcpoptions)
        send(ackpacket)
        #generate packets
        self.showstatus("generating packets...")
        try:
            originalpacket=IP(dst=ipaddress)/TCP(sport=sport,dport=dport,flags="PA",ack=receivepacket.seq+1,seq=receivepacket.ack,window=receivepacket.window,options=tcpoptions)/tcppayload
            #tcp segmentation
            if self.getoption('breaktcp'):
                packetlist=tcpsegmentation(originalpacket,self.getoption('tcpsegmentby'))
            else:
                packetlist=[originalpacket.copy()]
            #packetlist => [seg1,seg2,seg3...] or [packet]

            addtionalfunctions=[]
            #fake ttl
            if self.getoption('fakettl'):
                fakettlmodifyfunc,desc=(garbagepacket,'fakettl-junk') if 'junk' in self.getoption('fakettltype') else (rstpacket,'fakettl-rst')
                addtionalfunctions.append(lambda pck:(setttl(fakettlmodifyfunc(pck),self.getoption('ttlnum')),desc) )
            #bad checksum
            if self.getoption('badchecksum'):
                badchecksummodifyfunc,desc=(garbagepacket,'badchecksum-junk') if 'junk' in self.getoption('badchecksumtype') else (rstpacket,'badchecksum-rst')
                addtionalfunctions.append(lambda pck:(fuckupchecksum(badchecksummodifyfunc(pck)),desc))
            #corrupt ack
            if self.getoption('corruptack'):
                corruptackmodifyfunc,desc=(garbagepacket,'corruptack-junk')
                addtionalfunctions.append(lambda pck:(fuckupack(corruptackmodifyfunc(pck)),desc))
            #ip fragmentation the original packet if it is needed
            if self.getoption('breakip'):
                addtionalfunctions.append(lambda pck:(ipfragmentation(pck,self.getoption('ipfragmentby')),'ipfragmentation') )
            else:
                addtionalfunctions.append(lambda pck:(pck,'normal') )
            
            #make them to packetgroups
            packetgroups=[[func(pck) for func in addtionalfunctions] for pck in packetlist]
            #packetgroups=>[[f1(seg1),f2(seg1),f3(seg3)...],[f1(seg2),f2(seg2),f3(seg3)...]]
        except Exception as err:
            traceback.print_exc(err)
            return False,'failed to generate packets for: '+str(err)

        #shuffle
        if self.getoption('shuffle'):
            random.shuffle(packetgroups)
        
        #send packets
        for i,pckgroup in enumerate(packetgroups):
            # self.showstatus("[*]Sending packet group: %d/%d"%(i+1,len(packetslist)))
            for packandtype in pckgroup:
                pck,pcktype=packandtype
                self.showstatus("[*]Sending packet group :%d/%d packet type:%s"%(i+1,len(packetgroups),pcktype))
                send(pck)
                time.sleep(self.getoption('sleeptime'))
        self.showstatus('done... waiting for remaining packets...')
        time.sleep(5)
        return True,'done'

    def run(self):
        success,errmsg=self.sendpackets()
        if hasattr(self,'sniffer'):
            print('stop sniffer after running')
            self.sniffer.stop()
        if success:
            self.statustrigger.emit("sent success")
        else:
            self.statustrigger.emit("sent failed")
            self.qmessagetrigger.emit(errmsg)



class MyMainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyMainForm, self).__init__(parent)
        self.setupUi(self)
        #send button
        self.sendButton.clicked.connect(self.send_wrap)
        #stop button
        self.stopButton.clicked.connect(self.stopsend)
        #int forms constraint
        self.intforms=['sport','dport','tcpsegmentby','ipfragmentby','ttlnum']
        for intform in self.intforms:
            getattr(self,intform).setValidator(QIntValidator())
        #double forms constraint
        self.doubleforms=['sleeptime']
        for doubleform in self.doubleforms:
            getattr(self,doubleform).setValidator(QDoubleValidator())
        #sendthread
        self.sendthread=SendThread(self)
        #table lock
        self.tablelock=QMutex()
        #view packet detail
        self.receivedpackets.cellClicked.connect(self.viewpacketdetail)
        self.receivedpackets.cellEntered.connect(self.viewpacketdetail)
        #about
        self.actionAbout.triggered.connect(self.about)
        #usage
        self.actionUsage.triggered.connect(self.usage)

    def about(self):
        dialog=QDialog()
        x=Ui_aboutdialog()
        x.setupUi(dialog)
        dialog.setWindowTitle("About")
        dialog.exec_()
    
    def usage(self):
        QDesktopServices.openUrl(QUrl("https://github.com/TomAPU/ev/blob/master/README.md"))
    
    def send_wrap(self):
        try:
            self.send()
        except Exception as e:
            QMessageBox.critical(self, "Error", "un expected error occured: %s"%e)
    
    def viewpacketdetail(self,row,col):
        self.tablelock.lock()
        #get info
        protocol=self.receivedpackets.item(row,0).text()
        flags=self.receivedpackets.item(row,1).text()
        ttl=self.receivedpackets.item(row,2).text()
        payload=self.receivedpackets.item(row,3).text()
        self.tablelock.unlock()
        #make html content
        htmlcontent="<strong>Protocol:%s</strong>" % protocol
        htmlcontent+="<br/><strong>TCP Flags:%s</strong>" % flags
        htmlcontent+="<br/><strong>TTL:%s</strong>" % ttl
        htmlcontent+="<br/><strong>==========Payload=======</strong><br/>"
        if len(payload)==0:
            htmlcontent+="<br/><strong>No payload</strong>"
        else:
            payload=literal_eval(payload)
            for asciinum in payload:
                if asciinum==13 or asciinum==10:
                    htmlcontent+="<br/>"
                #check if printable
                elif asciinum>=32 and asciinum<=126:
                    htmlcontent+="&#%d;"%asciinum
                #not printable show in hex style
                else:
                    htmlcontent+=f'<span style="color:red">\\x%s</span>' % hex(asciinum)[2:].rjust(2,'0')
        #show info in packetdetail
        self.packetdetail.setHtml(htmlcontent)
    
    def send(self):
        #clear table
        self.cleartable()
        # start thread
        self.sendthread.start()

    def stopsend(self):
        self.sendthread.stop()
        self.displaystatus("Stopped")

    def displaystatus(self,status):
        self.statusbar.showMessage(status)
    
    def displayqmessage(self,qmessage):
        QMessageBox.information(self, "Warning", qmessage)
    
    def displayreceivedpackets(self,protocol,flags,ttl,payload):
        #lock
        self.tablelock.lock()
        table=self.receivedpackets
        row = table.rowCount()
        table.setRowCount(row+1)
        table.setItem(row, 0, QTableWidgetItem(protocol))
        table.setItem(row, 1, QTableWidgetItem(flags))
        table.setItem(row, 2, QTableWidgetItem(ttl))
        table.setItem(row, 3, QTableWidgetItem(payload))
        #unlock
        self.tablelock.unlock()

    def cleartable(self):
        self.tablelock.lock()
        self.receivedpackets.setRowCount(0)
        self.tablelock.unlock()





if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MyMainForm()
    win.show()
    sys.exit(app.exec())
