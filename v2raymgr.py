# import socket programming library 
import socket 
# import thread module 
from _thread import *
import threading 
import uuid
from client import Client, VMessInbound
import struct
import time
import hashlib
import json
import sqlite3

key='mitikoman'
vport=62789
lport=12345
dbpath='/opt/users.db'
itag='v6001'

print_lock = threading.Lock() 

cl=Client ( "127.0.0.1" , vport )
conn = sqlite3.connect(dbpath)
cr = conn.cursor()
cr.execute('''CREATE TABLE IF NOT EXISTS users (port int PRIMARY KEY, password text, dl decimal, ul decimal)''')
cr.execute('SELECT port,password FROM users')
all=cr.fetchall()
for urow in all:
    uport=str(urow[0])+'@v.com'
    upasswd=uuid.UUID(urow[1]).hex
    try:
        cr.add_user(itag,uport,upasswd,0,16)
        break
    except:
        print(urow[0],'already ')
conn.commit()
conn.close()
conn=0
cr=0

def packData(x):
    msg=json.dumps(x)    
    return struct.pack('!I',len(msg))+bytes(msg,'utf-8')

#switcher
def  List(msg,conn,cr):
    cr.execute('SELECT port,password FROM users')
    result=[]
    all=cr.fetchall()
    for urow in all:
        result.append({'port':urow[0],'password': urow[1]})
    return result

def  Add(msg,conn,cr):
    iport=msg['port']
    port=str(iport)
    password=msg['password']
    uid=uuid.UUID(password[0:32])
    suid=str(uid)
    cr.execute('SELECT count(port) FROM users WHERE password=?', [suid])
    num=cr.fetchone()[0]
    if (num>0):
        print('duplicate')
#        raise
        return {'port':iport, 'password':suid}
    cr.execute('INSERT OR IGNORE INTO users VALUES (?,?,?,?)',[iport,suid,0,0])
    cl.add_user(itag, uid.hex, port+'@v.com', 0, 16)
    conn.commit()
    return {'port': iport, 'password': password }


def  Delete(msg,conn,cr):
    iport=msg['port']
    port=str(iport)
    cl.remove_user(itag, port+'@v.com')
    cr.execute('DELETE FROM users WHERE port=?', [iport])
    conn.commit()
    return { 'port': iport }


def  Flow(msg,conn,cr):
    #port=msg['port']
    cr.execute('SELECT port,dl,ul FROM users')
    result=[]
    lstupd=[]
    all=cr.fetchall()
    for urow in all:
        port=urow[0]
        cport=str(port)+'@v.com'
        #passwd=urow['password']
        uplink=cl.get_user_traffic_uplink(cport) or 0
        downlink=cl.get_user_traffic_downlink(cport) or 0
        ddl=downlink-int(urow[1] or 0)
        dul=uplink-int(urow[2] or 0)
        lstupd.append((downlink,uplink,port))
        result.append({'port':port,'sumFlow': downlink+uplink})
    
    cr.executemany('UPDATE users SET dl=? ,ul=? WHERE port=?',lstupd)
    conn.commit()
    return result

def  Version(msg,conn,cr):
    return { 'type': 'version', 'version': '1.0.32' }

def Error(msg,conn,cr):
    print('error command! '+ msg)
    return

switchers = {
  'list':List,
  'add':Add,
  'del':Delete,
  'flow':Flow,
  'version':Version
  }
def goCommand(msg):
    #global conn
    conn = sqlite3.connect(dbpath)
    #global cr
    cr = conn.cursor()

    # Get the function from switcher dictionary
    func = switchers.get(msg['command'], Error)
    # Execute the function
    res=func(msg,conn,cr)
    conn.commit()
    conn.close()

    return res
# thread function 
def threaded(c): 
    while True: 
  
        # data received from client
        lenBuff=c.recv(2)
        if (len(lenBuff)<2):
            break
        lenBucket=(lenBuff[0] *256)+ lenBuff[1]
        print('Recieved size:',lenBucket)
        np=c.recv(lenBucket)
        if (not np or (len(np) <lenBucket)):
            print('bad packet!  bye!')
            return
        #newbuff=struct.pack('!Q',num)[2:]
        #CHECK TIME FOR OUTDATED PACKET!
        ptime=struct.unpack('!Q',b'\x00\x00'+np[:6])[0]
        ctime=round(time.time()*1000)
        if (abs(ctime - ptime) > 10 * 60 * 1000):
            print('Invalid message: Timed out.')
            break  

        #CHECK HASH CODE
        data=np[:-4];
        code=np[-4:];
        ucode=struct.unpack('!I',code)[0]
        command=np[6:-4];
        bptime=str(ptime)
        compon=bptime+command.decode("utf-8")+key
        #print('recieved:',compon)
        hash = hashlib.md5(bytes(compon,'utf-8') ).hexdigest()[0:8]
        #print('hash:',int(hash,16),'  code:',ucode)
        if (int(hash,16) != ucode):
            print('Invalid message: Hash mismatch. (Incorrect password)')
            c.send(packData({'Code':2}))
            break  
        req=json.loads(command)
        res=goCommand(req)
        if (type(res)==int):
            res={'code':res}
        else:
            res={'code':0,'data':res}
        print('result:',res)
        res=packData(res)
        c.send(res) 
#        break
    # connection closed 
    c.close() 
  
  
def Main(): 
    host = "" 
    # reverse a port on your computer 
    # in our case it is 12345 but it 
    # can be anything 
    #port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, lport)) 
    print("socket binded to port", lport) 
    # put the socket into listening mode 
    s.listen(1) 
    print("socket is listening") 
    # a forever loop until client wants to exit 
    while True: 
        c, addr = s.accept() 
        print('Connected to :', addr[0], ':', addr[1]) 
        start_new_thread(threaded, (c,)) 
    s.close() 
if __name__ == '__main__': 
    Main() 
