from twisted.internet.protocol import DatagramProtocol

from twisted.internet import reactor
import time
import binascii
import re
import  datetime
import thread
import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
console = logging.StreamHandler()

# set a format which is simpler for console use
formatter = logging.Formatter('LINE %(lineno)-4d : %(levelname)-8s %(message)s');
# tell the handler to use this format
console.setFormatter(formatter);
#logging.getLogger('').addHandler(console);
logger.addHandler(console);

clent_mess=[]
call_flag=0
equ_gloal={}
sys_time_cycle=0



class equ_para:
    def __init__(self):
        self.heart_time='01'
        self.sampling_time='000a'
        self.sleep_time='0000'
        self.online_time='05a0'
        self.reset_time='00001e'
        self.ciphertext='31323334'
class equ_ip:
    def __init__(self):
        self.ip='3af7812a'
        self.port='1111'
        self.sim='F18616999629'
class message:
    def __init__(self):
        self.start_byte='68'
        self.id=''
        self.control_byte=''
        self.length=''
        self.data=''
        self.check=''
        self.end_byte='16'
        self.addr=()
        self.open_mess_flag=0
        self.mess_last_time=''
        self.get_mess_last_time=''
        self.signal=''
        self.voltage=''
        self.secret='31323334'
        self.equ_para1=equ_para()
        self.equ_ip1=equ_ip()
        self.mess_check_time=''
        self.mess_set_secret=''
        self.mess_set_para=''
        self.mess_set_ip=''
        self.mess_get_ip=''
        self.mess_reset=''
        self.mess0a_get_para=''
        self.mess0d_get_time=''
        self.mess6a_get_para=''
        self.mess61_get_work=''
        self.mess61_back_work=''
        self.online=0
    def print_all(self):
        print 'start_byte:',self.start_byte
        print 'id:',self.id
        print 'control_byte:',self.control_byte
        print 'length:',self.length
        print 'data:',self.data
        print 'check:',self.check
        print 'end_byte:',self.end_byte
        print 'addr:',self.addr
        print 'mess_last_time:',self.mess_last_time
        print 'get_mess_last_time:',self.get_mess_last_time
        print 'signal:',self.signal
        print 'voltage:',self.voltage
        print 'open_mess_flag:',self.open_mess_flag


    def get_check_time(self):
        self.data=get_datetime()
        self.length='0006'
        self.control_byte='01'
        tmp=self.id+self.control_byte+self.length+ self.data
        self.check=mess_check(tmp)
        self.mess_check_time=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
        #SET SECRET
        #02H
    def set_secret(self):
        self.length='0008'
        self.control_byte='02'
        self.data=self.secret+self.secret
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess_set_secret=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
        #SET para
        #03H
    def set_para(self):
        self.length='0012'
        self.control_byte='03'
        self.data=self.secret+self.equ_para1.heart_time+self.equ_para1.sampling_time+self.equ_para1.sleep_time+self.equ_para1.online_time+self.equ_para1.reset_time+self.equ_para1.ciphertext
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess_set_para=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
    def set_ip(self):
        self.length='001C'
        self.control_byte='06'
        self.data=self.secret+self.equ_ip1.ip+self.equ_ip1.port+self.equ_ip1.ip+self.equ_ip1.port+self.equ_ip1.sim+self.equ_ip1.sim
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess_set_ip=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
    def get_ip(self):
        self.length='0000'
        self.control_byte='07'
        self.data=''
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess_get_ip=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
    def reset_equ(self):
        self.length='0002'
        self.control_byte='08'
        self.data=self.secret
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess_reset=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
    def get_para(self):
        self.length='0000'
        self.control_byte='0a'
        self.data=''
        tmp=self.id+self.control_byte+self.length+self.data
        self.check=mess_check(tmp)
        self.mess0a_get_para=self.start_byte+self.id+self.control_byte+self.length+ self.data+self.check+self.end_byte
    #0DH
    def get_time(self):
        self.length='0000'
        self.control_byte='0d'
        self.data = ''
        tmp = self.id + self.control_byte + self.length + self.data
        self.check = mess_check(tmp)
        self.mess0d_get_time = self.start_byte + self.id + self.control_byte + self.length + self.data + self.check + self.end_byte
    def get_para_6ah(self):
        self.length='0000'
        self.control_byte='6a'
        self.data=''
        tmp = self.id + self.control_byte + self.length + self.data
        self.check = mess_check(tmp)
        self.mess6a_get_para = self.start_byte + self.id + self.control_byte + self.length + self.data + self.check + self.end_byte
    def get_work_61h(self):
        self.length='0000'
        self.control_byte='61'
        self.data=''
        tmp = self.id + self.control_byte + self.length + self.data
        self.check = mess_check(tmp)
        self.mess61_get_work = self.start_byte + self.id + self.control_byte + self.length + self.data + self.check + self.end_byte
    def back_work_61h(self):
        self.length='0003'
        self.control_byte='61'
        self.data='00aa55'
        tmp = self.id + self.control_byte + self.length + self.data
        self.check = mess_check(tmp)
        self.mess61_back_work = self.start_byte + self.id + self.control_byte + self.length + self.data + self.check + self.end_byte
























def mess_check(data):
    tmp=len(data)
    i=0
    sum=0
    while i<(tmp/2):
        sum=sum+int(data[i*2:i*2+2],16)
        i=i+1
    result=hex(255-sum%256)
    result=(4 - len(result)) * '0' + result[2:]
    return result
def get_datetime():
    now=datetime.datetime.now()
    year=hex(now.year-2000)
    month=hex(now.month)
    day=hex(now.day)
    hour=hex(now.hour)
    minute=hex(now.minute)
    second=hex(now.second)
    result=(4 - len(year)) * '0' + year[2:]+(4 - len(month)) * '0' + month[2:]+(4 - len(day)) * '0' + day[2:]+(4 - len(hour)) * '0' + hour[2:]+(4 - len(minute)) * '0' + minute[2:]+(4 - len(second)) * '0' + second[2:]
    return result

def dictSort(key):
    if key in equ_gloal.keys():
        pass
    else:
        locals()['message'+str(len(equ_gloal))] =message()

        equ_gloal.update({key:locals()['message'+str(len(equ_gloal))]})





def mess_deal(self,data,addr,mess_time):
    #get start byte
    tmp=re.search('68',data)
    if tmp:
        a=int(tmp.span()[0])
        tmp_id = data[a + 2:a + 14]
        dictSort(tmp_id)
        equ_gloal[tmp_id].id = tmp_id
        equ_gloal[tmp_id].control_byte = data[a + 14:a + 16]
        equ_gloal[tmp_id].length = data[a + 16:a + 20]
        tmp = int(equ_gloal[tmp_id].length, 16)
        equ_gloal[tmp_id].data = data[a + 20:a + 20 + tmp * 2]
        tmp_check = mess_check(data[a + 2:a + 20 + tmp * 2])
        equ_gloal[tmp_id].check = data[a + 20 + tmp * 2:a + 20 + tmp * 2 + 2]
        if len(equ_gloal[tmp_id].addr) == 0:
            equ_gloal[tmp_id].addr += addr

        equ_gloal[tmp_id].get_mess_last_time = mess_time
        equ_gloal[tmp_id].print_all()

        if tmp_check == equ_gloal[tmp_id].check:
            # store id

            if equ_gloal[tmp_id].control_byte == '00':
                self.transport.write(data[a:].decode("hex"), addr)
                equ_gloal[tmp_id].open_mess_flag = 1

            if equ_gloal[tmp_id].control_byte == '01':
                equ_gloal[tmp_id].get_check_time()
                self.transport.write(equ_gloal[tmp_id].mess_check_time.decode("hex"), addr)
            if equ_gloal[tmp_id].control_byte == '02':
                if equ_gloal[tmp_id].data == 'ffff':
                    logging.warning('cmd:02h,set equ secret error')
                if equ_gloal[tmp_id].data == equ_gloal[tmp_id].secret + equ_gloal[tmp_id].secret:
                    logging.info('cmd:02h,set secret ok')

            if equ_gloal[tmp_id].control_byte == '03':
                if equ_gloal[tmp_id].data == 'ffff':
                    logging.warning('cmd:03h,set parameter error')
                if equ_gloal[tmp_id].length == '0012':
                    logging.info('cmd:03h,set para ok')

            if equ_gloal[tmp_id].control_byte == '05':
                # self.transport.write(data[a:].decode("hex"), addr)
                equ_gloal[tmp_id].mess_last_time = equ_gloal[tmp_id].data[0:12]
                equ_gloal[tmp_id].signal = equ_gloal[tmp_id].data[12:14]
                equ_gloal[tmp_id].voltage = equ_gloal[tmp_id].data[14:16]
                # check time
                time_tmp = equ_gloal[tmp_id].mess_last_time
                timelist = [int(time_tmp[0:2], 16) + 2000, int(time_tmp[2:4], 16), int(time_tmp[4:6], 16),
                            int(time_tmp[6:8], 16), int(time_tmp[8:10], 16), int(time_tmp[10:12], 16), 0, 0, 0]
                logging.info('get frame time:%s' % time.mktime(timelist))
                logging.info('the server time :%s' % time.time())
                if abs(time.mktime(timelist) - time.time()) > 120:
                    equ_gloal[tmp_id].get_check_time()

                    self.transport.write(equ_gloal[tmp_id].mess_check_time.decode("hex"), addr)
                    logging.info('%s send mess-01H-set time:%s' % (
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), equ_gloal[tmp_id].mess_check_time))

            if equ_gloal[tmp_id].control_byte == '06':
                if equ_gloal[tmp_id].data == 'ffff':
                    logging.warning('cmd:06h,set ip secret error')
                if equ_gloal[tmp_id].data == '0000':
                    logging.warning('cmd:06h,set ip data error')
                if equ_gloal[tmp_id].length == '001c':
                    logging.info('cmd:06h,set ip ok')
            if equ_gloal[tmp_id].control_byte == '07':
                equ_gloal[tmp_id].equ_ip1.ip = equ_gloal[tmp_id].data[0:8]
                equ_gloal[tmp_id].equ_ip1.port = equ_gloal[tmp_id].data[8:12]
                equ_gloal[tmp_id].equ_ip1.sim = equ_gloal[tmp_id].data[12:24]
                logging.info('cmd:07h,get ip ok')
            if equ_gloal[tmp_id].control_byte == '08':
                if equ_gloal[tmp_id].data == 'ffff':
                    logging.info('cmd:08h,reset error')
            if equ_gloal[tmp_id].control_byte == '0a':
                equ_gloal[tmp_id].equ_para1.heart_time = data[0:2]
                equ_gloal[tmp_id].equ_para1.sampling_time = data[2:6]
                equ_gloal[tmp_id].equ_para1.sleep_time = data[6:10]
                equ_gloal[tmp_id].equ_para1.online_time = data[10:14]
                equ_gloal[tmp_id].equ_para1.reset.time = data[14:20]
            if equ_gloal[tmp_id].control_byte == '0d':
                time_tmp = equ_gloal[tmp_id].data
                timelist = [int(time_tmp[0:2], 16) + 2000, int(time_tmp[2:4], 16), int(time_tmp[4:6], 16),
                            int(time_tmp[6:8], 16), int(time_tmp[8:10], 16), int(time_tmp[10:12], 16), 0, 0, 0]
                logging.info('cmd:0dh,get time:%s' % timelist)
            if equ_gloal[tmp_id].control_byte == '6a':
                logging.info('cmd:6ah,get para:%s' % equ_gloal[tmp_id].data)
            if equ_gloal[tmp_id].control_byte == '61':
                logging.info('cmd:61h,get work mess:%s' % equ_gloal[tmp_id].data)
                # send ok mess
                equ_gloal[tmp_id].back_work_61h()
                self.transport.write(equ_gloal[tmp_id].mess61_back_work.decode("hex"), addr)
                logging.info('%s send mess-61H-back work:%s' % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), equ_gloal[tmp_id].mess61_back_work))
            if equ_gloal[tmp_id].control_byte == '64':
                logging.info('cmd:64h,get work mess:%s' % equ_gloal[tmp_id].data)


        else:
            # print 'check error,right check:',tmp_check,'get check:',message_tmp.check
            logging.debug('check error,right check:%s,get check:%s' % (tmp_check, equ_gloal[tmp_id].check))

    else:
        logging.info('error mess format')






class Echo(DatagramProtocol):
    def datagramReceived(self, data, addr):
        #print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) , "received %r from %s" % (binascii.b2a_hex(data), addr)
        logging.info('Current time is %s'%time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        logging.info("received %r from %s" % (binascii.b2a_hex(data), addr))
        mess_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        mess_deal(self,binascii.b2a_hex(data),addr,mess_time)

        if addr not in clent_mess:
            clent_mess.append(addr)
            logging.info(clent_mess)



        #self.transport.write(data, addr)

        #call only once
        global call_flag
        if call_flag==0:
            self.printtime()
            call_flag=1

    def printtime(self):

        global sys_time_cycle
        sys_time_cycle+=1


        #print 'Current time is',time.strftime("%H:%M:%S")
        #logging.info('Current time is %s'%time.strftime("%H:%M:%S"))
        if sys_time_cycle==100:
            logging.info('Current time is %s'%time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            sys_time_cycle=0



        #for i in range(len(clent_mess)):
        #    self.transport.write('010203', clent_mess[i])
        for i in equ_gloal.keys():

            if sys_time_cycle==10:
                equ_gloal.get(i).set_secret()
                self.transport.write(equ_gloal.get(i).mess_set_secret.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess_set_secret))

            if sys_time_cycle==60:
                equ_gloal.get(i).set_para()
                self.transport.write(equ_gloal.get(i).mess_set_para.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess_set_para))

            if sys_time_cycle==40:
                equ_gloal.get(i).set_ip()
                self.transport.write(equ_gloal.get(i).mess_set_ip.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess_set_ip))

            if sys_time_cycle==30:
                equ_gloal.get(i).get_ip()
                self.transport.write(equ_gloal.get(i).mess_get_ip.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess_get_ip))
            if sys_time_cycle==50:
                equ_gloal.get(i).reset_equ()
                self.transport.write(equ_gloal.get(i).mess_reset.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess_reset))
            if sys_time_cycle==20:
                 equ_gloal.get(i).get_para()
                 self.transport.write(equ_gloal.get(i).mess0a_get_para.decode("hex"), equ_gloal.get(i).addr)
                 logging.info('%s send mess:%s'%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),equ_gloal.get(i).mess0a_get_para))
            #get time 0DH
            if sys_time_cycle==70:
                equ_gloal.get(i).get_time()
                self.transport.write(equ_gloal.get(i).mess0d_get_time.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess-0DH-get time:%s' % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), equ_gloal.get(i).mess0d_get_time))
            if sys_time_cycle==80:
                equ_gloal.get(i).get_para_6ah()
                self.transport.write(equ_gloal.get(i).mess6a_get_para.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess-0DH-get time:%s' % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), equ_gloal.get(i).mess6a_get_para))
            if sys_time_cycle==90:
                equ_gloal.get(i).get_work_61h()
                self.transport.write(equ_gloal.get(i).mess61_get_work.decode("hex"), equ_gloal.get(i).addr)
                logging.info('%s send mess-0DH-get time:%s' % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), equ_gloal.get(i).mess61_get_work))




















            #self.transport.write('88888888',equ_gloal.get(i).addr)




        reactor.callLater(1,self.printtime)


def main():
    reactor.callLater(3,main)
    print 'Current time is',time.strftime("%H:%M:%S")


if __name__ == '__main__':
    #main()
    reactor.listenUDP(7001, Echo())
    reactor.run()





