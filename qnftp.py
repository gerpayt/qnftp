import socket, threading, os, sys, time
import hashlib, platform, stat
import urllib2
import StringIO
from socket import error as SocketError
import errno

#  convert python's encoding to utf8
reload(sys)
sys.setdefaultencoding('utf8')

listen_ip = "0.0.0.0"
listen_port = 21
conn_list = []
max_connections = 500
conn_timeout = 120

import qiniu.conf
import qiniu.rsf
import qiniu.rs
import qiniu.io
import qiniu.resumable_io

bucket_name = 'qiniuftp'
domain_name = 'qiniuftp.qiniudn.com'

class FtpConnection(threading.Thread):
    def __init__(self, fd):
        threading.Thread.__init__(self)
        self.fd = fd
        self.running = True
        self.setDaemon(True)
        self.alive_time = time.time()
        self.option_utf8 = False
        self.identified = False
        self.option_pasv = True
        self.username = ""
        self.prefix = "/"
        self.startpoint = 0
    def process(self, cmd, arg):
        cmd = cmd.upper();
        if self.option_utf8:
            arg = unicode(arg, "utf8").encode(sys.getfilesystemencoding())
        print "<<", cmd, arg, self.fd
        # Ftp Command
        if cmd == "BYE" or cmd == "QUIT":
            self.message(221, "Bye!")
            self.running = False
            return
        elif cmd == "USER":
            # Set Anonymous User
            if arg == "": arg = "anonymous"
            self.username = arg
            #if not os.path.isdir(self.home_dir):
            #    self.message(530, "User " + self.username + " not exists.")
            #    return
            #self.pass_path = self.home_dir + "/.xxftp/password"
            #if os.path.isfile(self.pass_path):
            self.message(331, "Password required for " + self.username)
            qiniu.conf.ACCESS_KEY = self.username
            #else:
            #self.message(230, "Identified!")
            #self.identified = True
            return
        elif cmd == "PASS":
            qiniu.conf.SECRET_KEY = arg
            rets, err = qiniu.rsf.Client().list_prefix(bucket_name, prefix=self.prefix)
            if not rets:
                self.message(530, "Not identified!")
                self.identified = False
            else:
                self.message(230, "Identified!")
                self.identified = True
            return
        elif not self.identified:
            self.message(530, "Please login with USER and PASS.")
            return

        self.alive_time = time.time()
        finish = True
        if cmd == "NOOP":
            self.message(200, "ok")
        elif cmd == "TYPE":
            self.message(200, "ok")
        elif cmd == "SYST":
            self.message(200, "UNIX")
        elif cmd == "EPSV" or cmd == "PASV":
            #self.message(500, "failed to create data socket.")
            self.option_pasv = True
            try:
                self.data_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.data_fd.bind((listen_ip, 0))
                self.data_fd.listen(1024)
                ip, port = self.data_fd.getsockname()
                if cmd == "EPSV":
                    self.message(229, "Entering Extended Passive Mode (|||" + str(port) + "|)")
                else:
                    ipnum = socket.inet_aton(ip)
                    self.message(227, "Entering Passive Mode (%s,%u,%u)" %
                        (",".join(ip.split(".")), (port>>8&0xff), (port&0xff)))
            except:
                self.message(500, "failed to create data socket.")
        elif cmd == "EPRT":
            self.message(500, "implement EPRT later...")
        elif cmd == "PORT":
            self.option_pasv = False
            self.data_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = arg.split(",")
            self.data_ip = ".".join(s[:4])
            self.data_port = int(s[4])*256 + int(s[5])
            self.message(200, "ok")
        elif cmd == "PWD" or cmd == "XPWD":
            self.message(257, '"' + self.prefix + '"')
        elif cmd == "LIST" or cmd == "NLST":
            if arg != "" and arg[0] == "-": arg = "" # omit parameters
            # TODO
            #if not os.path.exists(local):
            #    self.message(550, "failed.")
            #    return
            if not self.establish(): return
            self.message(150, "ok")

            #maker = None
            #print self.prefix
            rets, err = qiniu.rsf.Client().list_prefix(bucket_name, prefix=self.prefix)
            #print rets
            if rets.has_key('marker') and not rets['marker']:#err is not None:
                #sys.stderr.write('error: %s ' % err)
                self.message(550, "failed."+err)
                return
            for file in rets['items']:
                file['key'] = file['key'][len(self.prefix.decode('utf8')):]
                if file['key'].endswith('/.') and file['key'].count('/') == 1:
                    file['key'] = file['key'][:-2]
                    is_dir = True
                elif file['key'].count('/')==0:
                    is_dir = False
                else:
                    continue
                if file['key'] == '.': continue
                info = "%srwxrwxrwx %04u %8s %8s %8lu %s %s\r\n" % (
                        "d" if is_dir else "-" , 1, "0", "0", file['fsize'],
                        time.strftime("%b %d %Y", time.localtime(file['putTime']/10000000)),
                        file['key'].encode("utf8"))
                #print info.strip()
                self.data_fd.send(info)
            '''for f in os.listdir(local):
                if f[0] == ".": continue
                path = local + "/" + f
                if self.option_utf8:
                    f = unicode(f, sys.getfilesystemencoding()).encode("utf8")
                if cmd == "NLST":
                    info = f + "\r\n"
                else:
                    st = os.stat(path)
                    info = "%s%s%s------- %04u %8s %8s %8lu %s %s\r\n" % (
                        "-" if os.path.isfile(path) else "d", "r", "w",
                        1, "0", "0", st[stat.ST_SIZE],
                        time.strftime("%b %d %Y", time.localtime(st[stat.ST_MTIME])),
                        f)
                print info
                self.data_fd.send(info)'''
            self.message(226, "Directory send OK." )
            self.data_fd.close()
            self.data_fd = 0
        elif cmd == "REST":
            self.startpoint = int(arg)
            self.message(250, "ok")
        elif cmd == "FEAT":
            #features = "211-Features:\r\nSITES\r\nEPRT\r\nEPSV\r\nMDTM\r\nPASV\r\n"\
            #    "REST STREAM\r\nSIZE\r\nUTF8\r\n211 End\r\n"
            features = "211-Features:\r\nSITES\r\nEPRT\r\nEPSV\r\n"\
                "REST STREAM\r\nUTF8\r\n211 End\r\n"
            self.fd.send(features)
        elif cmd == "OPTS":
            arg = arg.upper()
            if arg == "UTF8 ON":
                self.option_utf8 = True
                self.message(200, "ok")
            elif arg == "UTF8 OFF":
                self.option_utf8 = False
                self.message(200, "ok")
            else:
                self.message(500, "unrecognized option")
        elif cmd == "CDUP":
            #print 'prefix',self.prefix
            new_prefix = self.prefix[:self.prefix.rstrip('/').rfind('/')+1]
            #print new_prefix
            rets, err = qiniu.rsf.Client().list_prefix(bucket_name, prefix=new_prefix+'.', limit=1)
            if err is not None:
                self.message(550, "failed.")
            else:
                self.prefix = new_prefix
                self.message(250, '"' + self.prefix + '"')
        else:
            finish = False
        if finish: return
        # Parse argument ( It's a path )
        if arg == "":
            self.message(500, "where's my argument?")
            return
        #remote, local = self.parse_path(arg)
        # can not do anything to virtual directory
        #newpath = local
        #try:
        if cmd == "CWD":
            if arg == '': arg = '/'
            if arg.startswith('/'):
                new_prefix = arg.rstrip('/') + '/'
            else:
                new_prefix = self.prefix + arg.rstrip('/') + '/'
            #print 'new_prefix',new_prefix
            rets, err = qiniu.rsf.Client().list_prefix(bucket_name, prefix=new_prefix+'.', limit=1)
            #print err
            if err is not None:
                self.message(550, "failed.")
            else:
                self.prefix = new_prefix
                self.message(250, '"' + self.prefix + '"')
        elif cmd == "MDTM":
            dest_path = self.prefix + arg.rstrip('/')
            #print dest_path
            ret, err = qiniu.rs.Client().stat(bucket_name, dest_path)
            #print 'MDTM',err
            if err is not None:
                self.message(550, "failed")
            else:
                self.message(213, time.strftime("%Y%m%d%I%M%S", time.localtime(ret['putTime']/10000000)))
        elif cmd == "SIZE":
            dest_path = self.prefix + arg.rstrip('/')
            ret, err = qiniu.rs.Client().stat(bucket_name, dest_path)
            if err is not None:
                ret, err = qiniu.rs.Client().stat(bucket_name, dest_path+'/.')
                if err is not None:
                    self.message(550, "failed")
                    return
                else:
                    size = 4096
                    self.message(231, size)
                    return
            else:
                size = ret['fsize']
            self.message(231, size)
        elif cmd == "XMKD" or cmd == "MKD":
            dest_path = self.prefix + arg.rstrip('/')
            ret, err = qiniu.rs.Client().stat(bucket_name, dest_path)
            if err is None:
                self.message(550, "failed.")
            new_path = self.prefix + arg.rstrip('/') + '/.'
            extra = qiniu.io.PutExtra()
            extra.mime_type = "folder"
            empty_file = "."
            policy = qiniu.rs.PutPolicy(bucket_name)
            uptoken = policy.token()
            ret, err = qiniu.io.put(uptoken, new_path, empty_file, extra)
            if err is not None:
                #sys.stderr.write('error: %s ' % err)
                self.message(550, "failed.")
            self.message(250, "ok")
        elif cmd == "RNFR":
            if arg.startswith('/'):
                self.temp_path = arg.rstrip('/')
            else:
                self.temp_path = self.prefix + arg.rstrip('/')
            self.message(350, "rename from " + self.temp_path)
        elif cmd == "RNTO":
            if arg.startswith('/'):
                dest_path = arg.rstrip('/')
            else:
                dest_path = self.prefix + arg.rstrip('/')
            #src_path = self.prefix + arg.rstrip('/')
            #ret, err = qiniu.rs.Client().stat(bucket_name, src_path)
            #if err is None:
            #    self.message(550, "failed.")
            #new_path = self.prefix + arg.rstrip('/') + '/.'
            #print self.temp_path
            ret, err = qiniu.rs.Client().stat(bucket_name, self.temp_path )
            #print err
            if err is None: # file
                ret, err = qiniu.rs.Client().move(bucket_name, self.temp_path, bucket_name, dest_path)
                #print err
                if err is not None:
                    self.message(550, "failed.")
                    return
            else:
                ret, err = qiniu.rs.Client().stat(bucket_name, self.temp_path + '/.' )
                if err is None: # folder
                    ret, err = qiniu.rs.Client().move(bucket_name, self.temp_path + '/.', bucket_name, dest_path+ '/.')
                    rets, err = qiniu.rsf.Client().list_prefix(bucket_name, prefix=self.temp_path + '/')
                    #print rets
                    for file in rets['items']:
                        src = file['key']
                        dst = dest_path + src[len(self.temp_path):]
                        ret, err = qiniu.rs.Client().move(bucket_name, src, bucket_name, dst)
                        #print err
                else:
                    pass
            self.message(250, "RNTO to " + dest_path)
        elif cmd == "XRMD" or cmd == "RMD":
            dest_path = self.prefix + arg.rstrip('/') + '/.'
            ret, err = qiniu.rs.Client().delete(bucket_name, dest_path)
            self.message(250, "ok")
        elif cmd == "DELE":
            dest_path = self.prefix + arg
            ret, err = qiniu.rs.Client().delete(bucket_name, dest_path)
            #if err is not None:
            #    self.message(550, "failed.")
            #else:
            self.message(250, "ok")
        elif cmd == "RETR":
            #if not os.path.isfile(newpath):
            #    self.message(550, "failed")
            #    return
            src_path = self.prefix + arg
            ret, err = qiniu.rs.Client().stat(bucket_name, src_path)
            #print ret
            if err is not None:
                self.message(550, "failed.")
            if not self.establish(): return
            self.message(150, "ok")
            base_url = qiniu.rs.make_base_url(domain_name, src_path)
            policy = qiniu.rs.GetPolicy()
            private_url = policy.make_request(base_url)
            #print private_url
            request = urllib2.Request(private_url)
            #print "Range", "bytes=%d-%d" % (self.startpoint, ret['fsize'])
            request.add_header("Range", "bytes=%d-%d" % (self.startpoint, ret['fsize']))
            response = urllib2.urlopen(request)
            while self.running:
                self.alive_time = time.time()
                #data = response.read(8192)
                #data = response.read(1024*1024)
                data = response.read(4*1024)
                # TODO ?
                if len(data) == 0: break
                self.data_fd.send(data)
            response.close()
            self.startpoint = 0
            self.data_fd.close()
            self.data_fd = 0
            self.message(226, "ok")
        elif cmd == "STOR" or cmd == "APPE":
            dest_path = self.prefix + arg
            ret, err = qiniu.rs.Client().stat(bucket_name, dest_path+'/.')
            if err is None:
                self.message(550, "failed.")
            if not self.establish(): return
            self.message(150, "ok")

            dest_path = self.prefix + arg
            if cmd == "STOR":
                ret, err = qiniu.rs.Client().stat(bucket_name, dest_path)
                #print ret
                if err is None:
                    ret, err = qiniu.rs.Client().delete(bucket_name, dest_path)
                    if err is not None:
                        self.message(550, "failed.")
                        return

            policy = qiniu.rs.PutPolicy(bucket_name)
            uptoken = policy.token()
            extra = qiniu.resumable_io.PutExtra(bucket_name)
            buf = ''
            while self.running:
                self.alive_time = time.time()

                try:
                    data = self.data_fd.recv(8192)
                except SocketError as e:
                    #print "err356",e
                    #if e.errno != errno.ECONNRESET:
                    #    raise # Not error we are looking for
                    pass # Handle error here.
                #data = self.data_fd.recv(4*1024*1024)
                #print 'data',len(data)
                if len(data) == 0: break
                buf += data
            ret, err = qiniu.resumable_io.put(uptoken, dest_path, StringIO.StringIO(buf), len(buf), extra)
            #print 'ret',ret,err

            if err is not None:
                #sys.stderr.write('error: %s ' % err)
                self.message(550, "failed.")
            self.message(250, "ok")

            #print ret

            self.data_fd.close()
            self.data_fd = 0
            self.message(226, "ok")
        else:
            self.message(500, cmd + " not implemented")
            self.startpoint = 0
    #except:
    #    self.message(550, "failed.")

    def establish(self):
        if self.data_fd == 0:
            self.message(500, "no data connection")
            return False
        if self.option_pasv:
            fd = self.data_fd.accept()[0]
            self.data_fd.close()
            self.data_fd = fd
        else:
            try:
                self.data_fd.connect((self.data_ip, self.data_port))
            except:
                self.message(500, "failed to establish data connection")
                return False
        return True

    def run(self):
        ''' Connection Process '''
        try:
            if len(conn_list) > max_connections:
                self.message(500, "too many connections!")
                self.fd.close()
                self.running = False
                return
            # Welcome Message
            self.message(220, "xxftp(Python) www.xiaoxia.org")
            # Command Loop
            line = ""
            while self.running:
                data = self.fd.recv(4096)
                if len(data) == 0: break
                line += data
                if line[-2:] != "\r\n": continue
                line = line[:-2]
                space = line.find(" ")
                if space == -1:
                    self.process(line, "")
                else:
                    self.process(line[:space], line[space+1:])
                line = ""
        except:
            print "error", sys.exc_info()
        self.running = False
        self.fd.close()
        print "connection end", self.fd, "user", self.username

    def message(self, code, s):
        ''' Send Ftp Message '''
        print '>>', code, s
        s = str(s).replace("\r", "")
        ss = s.split("\n")
        if len(ss) > 1:
            r = (str(code) + "-") + ("\r\n" + str(code) + "-").join(ss[:-1])
            r += "\r\n" + str(code) + " " + ss[-1] + "\r\n"
        else:
            r = str(code) + " " + ss[0] + "\r\n"
        if self.option_utf8:
            r = unicode(r, sys.getfilesystemencoding()).encode("utf8")
        self.fd.send(r)

def server_listen():
    global conn_list
    listen_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_fd.bind((listen_ip, listen_port))
    listen_fd.listen(1024)
    conn_lock = threading.Lock()
    print "ftpd is listening on ", listen_ip + ":" + str(listen_port)

    while True:
        conn_fd, remote_addr = listen_fd.accept()
        print "connection from ", remote_addr, "conn_list", len(conn_list)
        conn = FtpConnection(conn_fd)
        conn.start()

        conn_lock.acquire()
        conn_list.append(conn)
        # check timeout
        try:
            curr_time = time.time()
            for conn in conn_list:
                if int(curr_time - conn.alive_time) > conn_timeout:
                    if conn.running == True:
                        conn.fd.shutdown(socket.SHUT_RDWR)
                    conn.running = False
            conn_list = [conn for conn in conn_list if conn.running]
        except:
            print sys.exc_info()
        conn_lock.release()


def main():
    server_listen()
    
if __name__ == "__main__":
    main()


