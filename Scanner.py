# encoding=utf8
import socket
from Tkinter import *
import threading
import time
from tkMessageBox import *
import subprocess
import sys
import urllib2
import ttk
import os
import subprocess
from tkSimpleDialog import *
import warnings


class Scanner:
    def __init__(self, master):
        self.master = master
        self.master.bind('<Button-1>', self.show_properties)
        self.IPs = []
        self.finished_port = False
        Label(master, text='Starting IP:').grid(row=0, column=0)
        self.ip_mac_pairs = {}

        self.e = Entry(master)
        self.e.grid(row=0, column=1)
        Label(master, text='Ending IP:').grid(row=0, column=2)

        self.e2 = Entry(master)
        self.e2.grid(row=0, column=3)

        self.b = Button(master, text='Scan', command=lambda: self.wrapper(False, None, None))
        self.b.grid(row=0, column=4)

        self.properties_butt = Button(master, text='Properties', state=DISABLED, command=self.properties)
        self.properties_butt.grid(row=0, column=5)

        self.tree = ttk.Treeview(master)
        self.tree['columns'] = ('ip', 'name', 'mac_addr', 'company')
        self.tree.heading("ip", text="IP Address")
        self.tree.heading('name', text='Hostname')
        self.tree.heading('mac_addr', text='Mac Address')
        self.tree.heading("company", text='Vendor Name')
        self.tree['displaycolumns'] = ('ip', 'name', 'mac_addr', 'company')
        self.tree['show'] = 'headings'
        self.tree.grid(row=1, column=0, columnspan=5)
        start = time.clock()

        self.threads = []
        try:
            f = open('data.dat', 'r')
            lines = f.read().splitlines()
            last_scan_unix, startip, endip = lines[0], lines[1], lines[2]
            self.e.insert(0, startip)
            self.e2.insert(0, endip)
            # Index Will Move Up - So 1st 3 - 0,0,0
            del lines[0]
            del lines[0]
            del lines[0]
            f.close()
            self.parse_from_file(lines)
            self.b.config(text='Refresh')
            diff = int(time.time()) - int(last_scan_unix)
            if diff >= 86400:
                # Forces Refresh
                raise IOError
        except IOError:
            lines = []
            if self.e.get() == '' or self.e2.get() == '':
                self.e.delete(0, 'end')
                self.e2.delete(0, 'end')
                self.e.insert(0, '192.168.0.0')
                self.e2.insert(0, '192.168.0.255')
                temp_e = self.e.get()
                temp_e2 = self.e2.get()
                self.wrapper(True, temp_e, temp_e2)
        finally:
            print 'creating table'
            self.table_wrapper()
            self.file_writer()
            print 'Total Time:', time.clock() - start
            tree_scroller = Scrollbar(master)
            tree_scroller.configure(command=self.tree.yview)
            self.tree.configure(yscrollcommand=tree_scroller.set)
            tree_scroller.grid(row=1, column=5, sticky='NSW')
            master.mainloop()

    def properties(self):
        new_tl = Toplevel(self.master)
        data = self.tree.selection()[0]
        row_data = self.tree.item(data)
        ip, mac = row_data['values'][0], row_data['values'][2]
        print ip, mac
        PropertiesMENU(new_tl, ip, mac)
        f = open('data.dat', 'r')
        lines = f.read().splitlines()
        last_scan_unix, startip, endip = lines[0], lines[1], lines[2]
        # Index Will Move Up - So 1st 3 - 0,0,0
        del lines[0]
        del lines[0]
        del lines[0]
        f.close()
        self.parse_from_file(lines)

    def show_properties(self, event):
        self.master.update()
        try:
            item = self.tree.selection()[0]
            if len(item) == 4:
                self.properties_butt.config(state=NORMAL)
        except:
            self.properties_butt.config(state=DISABLED)

    def parse_from_file(self, lines):
        # Order: ip,hn,mac_addr,vendor,'HOSTPC'
        for i in lines:
            if len(i) == 0:
                continue
            parts = i.split('~')
            try:
                f = open('hostnames.dat', 'r')
                l = f.read().splitlines()
                del l[0]
                f.close()
                hn_assoc = {}
                for m in l:
                    p = m.split('~')
                    hn_assoc[p[0]] = p[1]
            except IOError:
                hn_assoc = {}
            if len(parts) == 4:
                ip, hn, mac_addr, vendor = parts
                if mac_addr in hn_assoc.keys():
                    hn = hn_assoc[mac_addr]
                self.ip_mac_pairs[ip] = [hn, mac_addr, vendor]
            else:
                ip, hn, mac_addr, vendor, host_pc = parts
                if mac_addr in hn_assoc.keys():
                    hn = hn_assoc[mac_addr]
                self.ip_mac_pairs[ip] = [hn, mac_addr, vendor, host_pc]
        self.push_wrapper()

    def table_wrapper(self):
        print 'table wrapper'
        self.tree.delete(*self.tree.get_children())
        self.IPs = list(set(self.IPs))
        l = map(socket.inet_aton, self.IPs)
        l.sort()
        self.IPs = map(socket.inet_ntoa, l)
        for i in self.IPs:
            # Rudimentary Way To Put Host PC At Top of Treeview
            if i == socket.gethostbyname(socket.gethostname()):
                t = threading.Thread(target=lambda: self.setup_push(i, True))
            else:
                t = threading.Thread(target=lambda: self.setup_push(i, False))
            t.start()
            time.sleep(.1)
            if i == self.IPs[-1]:
                t.join()
        self.push_wrapper()

    def get_mac(self, ip):
        plat = sys.platform
        if plat == 'win32' or plat == 'cygwin':
            command = 'arp -a'
            lines, nothing = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              shell=True).communicate()
            lines = lines.split('\r\n')
            for i in lines:
                formatted = ' '.join(i.split())
                sections = formatted.split(' ')
                if sections[0] == ip:
                    return sections[1]
            else:
                command = 'ipconfig /all'
                lines, nothing = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                  shell=True).communicate()
                lines = lines.split('\r\n')
                for i in lines:
                    if i.lstrip().startswith('Physical Address'):
                        segments = i.split(':')
                        return segments[1].lstrip().lower()
        elif plat == 'linux' or plat == 'linux2':
            command = 'arp -n ' + str(ip)
            lines, nothing = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              shell=True).communicate()
            lines = lines.split('\n')
            for i in lines:
                if ip in i:
                    segments = (' '.join(i.split())).split(' ')
                    return segments[2].replace(':', '-').lower()

    def mac_lookup(self, mac):
        t = []
        for i in mac:
            try:
                i = i.lower()
            except:
                pass
            if i in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
                t.append(i)
        s = ''.join(t)
        s = s.upper()
        # Uses The MacVendors.co API (http://macvendors.co/api)
        response = urllib2.Request('https://macvendors.co/api/vendorname/' + s, headers={'User-Agent': "API Browser"})
        response = urllib2.urlopen(response)
        return response.read()

    def wrapper(self, stup, e, e2):
        if not stup:
            showinfo("Starting Scan", "Starting Scan:\nGUI May FREEZE \nThat Just Means The Program Is Working")
        if e == None:
            e = self.e.get()
            e2 = self.e2.get()
        self.Scan(e, e2)
        if not stup:
            showinfo("Finshed", "Finished!")
        print 'done'

    def setup_push(self, i, host_pc):
        try:
            mac_addr = self.get_mac(i)
            # HOST PC
            if mac_addr == None and (sys.platform == 'win32' or sys.platform == 'cygwin'):
                command = 'ipconfig /all'
                lines, nothing = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                  shell=True).communicate()
                for i in lines:
                    if i.lstrip().startswith('Physical Address'):
                        segments = i.split(':')
                        mac_addr = segments[1].lstrip().lower()
            vendor = self.mac_lookup(mac_addr)
            if vendor == None:
                vendor = 'Unknown Vendor'
            hn = socket.gethostbyaddr(i)[0]
            try:
                f = open('hostnames.dat', 'r')
                l = f.read().splitlines()
                del l[0]
                f.close()
                self.hn_assoc = {}
                for m in l:
                    p = m.split('~')
                    self.hn_assoc[p[0]] = p[1]
            except IOError:
                self.hn_assoc = {}
            finally:
                if not host_pc:
                    if mac_addr in self.hn_assoc.keys():
                        hn = self.hn_assoc[mac_addr]
                    self.ip_mac_pairs[i] = [hn, mac_addr, vendor]
                else:
                    if mac_addr in self.hn_assoc.keys():
                        hn = self.hn_assoc[mac_addr]
                    self.ip_mac_pairs[i] = [hn, mac_addr, vendor, 'HOSTPC']
        except socket.herror:
            mac_addr = self.get_mac(i)
            vendor = self.mac_lookup(mac_addr)
            if vendor == None:
                vendor = 'Unknown Vendor'
            try:
                f = open('hostnames.dat', 'r')
                l = f.read().splitlines()
                del l[0]
                f.close()
                self.hn_assoc = {}
                for m in l:
                    p = m.split('~')
                    self.hn_assoc[p[0]] = p[1]
            except IOError:
                self.hn_assoc = {}
            if mac_addr in self.hn_assoc.keys():
                hn = self.hn_assoc[mac_addr]
            else:
                hn = ''
            # Linux-Specific
            if vendor != "Please provide mac address":
                self.ip_mac_pairs[i] = [hn, mac_addr, vendor]

    def file_writer(self):
        print 'writing to file'
        lines = [str(int(time.time())), self.e.get(), self.e2.get()]
        with open('data.dat', 'w+') as f:
            for i in self.ip_mac_pairs.keys():
                vals = self.ip_mac_pairs[i]
                full_str = i + '~' + '~'.join(vals) + '\n'
                if full_str in f.readlines():
                    continue
                else:
                    lines.append(full_str)
            f.write("\n".join(lines))
        print 'finished writing'

    def push_wrapper(self):
        keylist = self.ip_mac_pairs.keys()
        l = map(socket.inet_aton, keylist)
        l.sort()
        keylist = map(socket.inet_ntoa, l)
        print 'push wrapper'
        for i in keylist:
            self.append_to_table(i, self.ip_mac_pairs[i])
        print 'done'

    def append_to_table(self, ip, vals):
        # Host PC
        if len(vals) == 4:
            vals[0] = vals[0].strip(".localdomain")
            self.tree.insert('', 0, text='', values=(ip, vals[0], vals[1], vals[2]))
        else:
            vals[0] = vals[0].strip(".localdomain")
            self.tree.insert('', 'end', text='', values=(ip, vals[0], vals[1], vals[2]))

    def Scan(self, e, e2):
        print 'started'
        print e
        print e2
        start_ip = e.split('.')
        end_ip = e2.split('.')
        try:
            socket.inet_aton('.'.join(start_ip))
            socket.inet_aton('.'.join(end_ip))
            # Checks If A And B Are Equal
            if start_ip[0] == end_ip[0] and start_ip[1] == end_ip[1]:
                if start_ip[2] <= end_ip[2]:
                    if start_ip[3] <= end_ip[3]:
                        pass
                    else:
                        raise ValueError
                else:
                    raise ValueError
            else:
                raise ValueError
        except socket.error:
            print 'sock'
            showerror("Invalid IP Address", "One Of Your IP Addresses Is Invalid")
            return None
        except ValueError:
            print 'value'
            showerror("Invalid Range", "Your IP Range Is Invalid")
            return None
        try:
            self.tcp_connect(start_ip[0], start_ip[1], start_ip[2], start_ip[3], end_ip[3])
            print 'pinging'
            self.ping_ports(start_ip[0], start_ip[1], start_ip[2], start_ip[3], end_ip[3])
            self.IPs = list(set(self.IPs))
            print len(self.IPs)
            l = map(socket.inet_aton, self.IPs)
            l.sort()
            self.IPs = map(socket.inet_ntoa, l)
            self.IPs = list(set(self.IPs))
        except:
            self.Scan(e, e2)

    def tcp_connect(self, a, b, c, d_min, d_max, TIMEOUT=.15):
        def connect_to_sock(ip, port, TIMEOUT):
            s = socket.socket()
            s.settimeout(TIMEOUT)
            global finished_D
            try:
                s.connect((ip, port))
                s.close()
                self.IPs.append(str(ip))
                self.finished_port = True
            except:
                s.close()
            if port == 1023:
                self.finished_port = True

        working_string = a + "." + b + "." + c + "."
        # No Port 53 b/c Often Connects W/O Actual Device
        common_ports = [13, 17, 19, 20, 21, 22, 23, 25, 37, 67, 68, 69, 80, 81, 110, 111, 113, 123, 135, 137, 138, 139,
                        143, 161, 162, 179, 389, 407, 443, 445, 500, 518, 520, 548, 587, 631, 635, 636, 989, 990, 993,
                        995, 1024, 1025, 1026, 1027, 1028, 1029, 1050, 1723, 1863, 2049, 2302, 3389, 3784, 4444, 4567,
                        5000, 5050, 5060, 5093, 5353, 5678, 7547, 7676, 8000, 8080, 8081, 8082, 8594, 8767, 8888, 9915,
                        9916, 9987, 10000, 12203, 12345, 18067, 27374, 27960, 27971, 28786, 28960, 28961, 28962, 28964,
                        29070, 29072, 29900, 29901, 29961, 30005, 30722, 34321, 34818, 49152, 49175, 50050, 50444,
                        56789, 62078, 63392, 63426, 64738]
        for i in range(int(d_min), int(d_max)):
            if i % 32 == 0:
                pass
            for p in common_ports:
                threading.Thread(target=lambda: connect_to_sock(working_string + str(i), p, TIMEOUT)).start()
                if self.finished_port:
                    self.finished_port = False
                    break

    def ping_ports(self, a, b, c, d_min, d_max):
        try:
            working_string = a + "." + b + "." + c + "."
            info = None
            if os.name == 'nt':
                info = subprocess.STARTUPINFO()
                info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                info.wShowWindow = subprocess.SW_HIDE
            for i in range(int(d_min), int(d_max) + 1):
                t = threading.Thread(target=lambda: self.do_ping(working_string + str(i), info)).start()
                time.sleep(.05)
            print 'done pinging'
        except Exception as e:
            print e

    def do_ping(self, ip, info):
        if sys.platform == 'win32' or sys.platform == 'cygwin':
            output = subprocess.Popen(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE,
                                      startupinfo=info).communicate()[0]
        elif sys.platform == 'linux1' or sys.platform == 'linux2':
            output = subprocess.Popen(['ping', '-c', '1', '-w', '1000', ip], stdout=subprocess.PIPE,
                                      startupinfo=info).communicate()[0]
        out = output.decode('utf-8')
        if "Destination host unreachable" in out or "Request timed out" in out:
            pass
        else:
            self.IPs.append(ip)


def on_closing():
    root.destroy()
    os._exit(0)


class PropertiesMENU:
    def __init__(self, master, ip, mac):
        self.master = master
        hostname_set = Button(master, text='Set Hostname', command=lambda: self.set_hn(mac))
        hostname_set.grid(row=0)
        ping_butt = Button(master, text="Ping " + ip, command=lambda: self.ping(ip))
        ping_butt.grid(row=1)

    def set_hn(self, mac):
        hn = askstring("Hostname", "What Should This Device Be Named?")
        if hn == None:
            return None
        temp = open('hostnames.dat', 'r')
        file_text = temp.readlines()
        temp.close()
        g = open('hostnames.dat', 'w+')
        g.seek(0)
        g.write('\n')
        print file_text
        ls = [line.rstrip('\n') for line in file_text]
        good_lines = []
        for i in ls:
            if not mac in i and not i == '':
                good_lines.append(i)
            else:
                good_lines.append(mac + '~' + hn)
        g.write("\n".join(good_lines))
        g.close()
        showinfo("Done", "Finished")
        showinfo("Refresh", "Table Will Be Refreshed With The New Hostname On Restart Of Program")
        self.master.destroy()

    def ping(self, ip):
        times = askinteger('Pings', "How Many Times Should the Host Be Pinged (Negative Number for Infinite)?")
        if times == None:
            return None
        tl = Toplevel()
        ping_menu(tl, times, ip)


class ping_menu:
    def __init__(self, master, ping_amount, ip):
        self.t = Text(master, state=DISABLED).grid(row=0)
        # self.p(ping_amount,ip)

    def p(self, amount, ip):
        if sys.platform == 'win32' or sys.platform == 'cygwin':
            p = subprocess.Popen(['ping', '-n', str(amount), str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif sys.platform == 'linux1' or sys.platform == 'linux2':
            p = subprocess.Popen(['ping', '-c', str(amount), str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            out = p.stdout.read(1)
            if out == '' and p.poll() != None:
                break
            if out != '':
                self.t.config(state=NORMAL)
                self.t.insert(END, '\n' + out)
                self.t.config(state=DISABLED)


if __name__ == '__main__':
    root = Tk()
    Scanner(root)
    os._exit(0)
