
hey_why_are_you_here=[
r"    __ __                             __  __",
r"   / // /__  ___  ___ __ _____  ___  / /_/ /",
r"  / _  / _ \/ _ \/ -_) // / _ \/ _ \/ __/_/ ",
r" /_//_/\___/_//_/\__/\_, / .__/\___/\__(_)  ",
r"                    /___/_/                "
]

i_think_you_are_sill=[
r"   __ _________________    ___  ____  ______   ",
r"  / // /_  __/_  __/ _ \  / _ \/ __ \/_  __/   ",
r" / _  / / /   / / / ___/ / ___/ /_/ / / /      ",
r"/_//_/ /_/   /_/ /_/    /_/   \____/ /_/   ____",
r"                                          /___/"
]

me_who_loves_getting=[
r"   __________ __   ___  ____  ______   ",
r"  / __/ __/ // /  / _ \/ __ \/_  __/   ",
r" _\ \_\ \/ _  /  / ___/ /_/ / / /      ",
r"/___/___/_//_/  /_/   \____/ /_/  ____",
r"                                 /___/"
]

me_into_every_problem_deeper_bitch=[

]

think_abt_it=[
r" __  __         __     __ __                             __  __",
r" \ \/ /__ ___ _/ /    / // /__  ___  ___ __ _____  ___  / /_/ /",
r"  \  / -_) _ `/ _ \  / _  / _ \/ _ \/ -_) // / _ \/ _ \/ __/_/ ",
r"  /_/\__/\_,_/_//_/ /_//_/\___/_//_/\__/\_, / .__/\___/\__(_)  ",
r"                                       /___/_/                 "
]

import subprocess
import time
import subprocess
import socket as sc
import paramiko as pk
import threading
import select

def start():
    process = subprocess.Popen("type one.txt", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    i=j=0
    for line in process.stdout:
        print("    ",line.decode().strip(),end="     \t")
        # print("",end="\t")
        i+=1
        if(i>=7 and j<5):
            # print(hey_why_are_you_here[j],end="",flush=True)
            print(hey_why_are_you_here[j],end="",flush=True)
            
            j+=1
            # time.sleep(0.0009)
        print()

    error = process.stderr.read().decode().strip()
    if error:
        print(f"Error: {error}")

def printer(word):
    for j in word:
        print("   \t",j,flush=True)
    print()

def defaults(soc):
    global IP, Queue, Soc
    IP = "0.0.0.0" 
    Queue = 5
    Soc = soc
    print("Defaults -- ")
    vals()
    # print("Port to be open :")

def vals():
        print("Host IP                :",IP,"\nPort number            :",Soc,"\nMax active connections :",Queue)

def des(un):
    try:
        while True:
            des = input("\nDo you want to continue with the default credentials? (yes/no)/(y/n)")
            des=des.lower()
            if des[0] == 'n':
                edit(un)
                break
            elif des[0] == 'y':
                break
            else:
                print("Confirm your choise - ",end="")
    except KeyboardInterrupt:
        print("Continuing to server with defaults")
        print(" Rolling back ",end="")
        load(0.2)
    finally:
        # time.sleep(0.5)
        pass

def vlas():
    print("Host IP :",IP,"\nPort no :",Soc,"\nMax active connections :",Queue,"\n")

def edit(un):
    global IP, Queue, Soc
    try:
        while True:
            print("# If you still don't to change some of them, just press enter in those options.")
            while True:
                t_IP = input("Enter the IP which the pot must be set (In format X.X.X.X) : ")
                if len(t_IP.split('.'))==4:
                    IP=t_IP
                    break
                elif t_IP == '':
                    IP = "0.0.0.0"
                    break
                else:
                    print("Try again, Do it in correct format ex: 127.0.0.1")
            while True:
                t_Soc = input("Enter the Port number the pot must listen(Kept Open) : ")
                if (str(t_Soc)).isnumeric():
                    Soc = int(t_Soc)
                    break
                elif t_Soc == '':
                    break
                else:
                    print("Try again, Input is in form of number only! range(0-65535).")
            while True:
                t_Queue = input("Enter the max no.of active conncetions to be held by pot : ")
                if (str(t_Queue)).isnumeric():
                    Queue = int(t_Queue)
                    break
                elif t_Queue == '':
                    break
                else:
                    print("Try again, Input is in form of number only!.")
            vals()
            f_in=input("Are you sure about your changes ? (yes/no)/(y/n)")
            print()
            if 'y' in f_in.lower():
                break
    except KeyboardInterrupt:
        print("Continuing to server with defaults")
        defaults(un)
        print("  No changes made!",end="")
        load(0.3)
        print()

def load(t=0.1):
    for i in range(3):
        for char in ["|","/","-","\\"]:
            print(char, end='\r')
            time.sleep(t)

def website(site):
    global web_data
    web = open(site,mode="r",encoding="utf-8")
    web_data = web.read()
    return (web_data).encode("utf-8")

def websiteopt():
    try:
        while True:
            print("\nWhich webite should be moked by the http service hosted, here comes the list --\nChoose the appropriate option..")
            print("[1][D] Instagram Login")
            print("[2] Blank Page")
            print("More under development will be added soon...")
            s_in = input()
            if s_in.strip() == '':
                print("Sorry again !") 
            elif s_in[0] == '1' :
                return(website("insta.html"))
            elif s_in[0] == "2":
                return((bytes("<h1></h1>".encode("utf-8"))))
            else:
                print("Sorry again !")
    except KeyboardInterrupt:
        print(" Proceding with the default - [D]",end="")
        load()
        print()
        return(website("insta.html"))
    
def HTTP_Pot():
    printer(i_think_you_are_sill)
    # print("ANSI HTTP Honeypot")
    defaults(80)
    global IP, Queue, Soc
    des(80)
    web_data = websiteopt()
    try:
        http_serv_sock =  sc.socket(sc.AF_INET,sc.SOCK_STREAM)
        http_serv_sock.bind((IP,Soc))
        http_serv_sock.listen(Queue)
        print(f"\nHTTP server running in {IP} . Check your browser with this IP address!\n")
        while True:
            readable,_,_ = select.select([http_serv_sock],[],[],0.1)
            if readable:
                http_cli_sock , http_cli_addr = http_serv_sock.accept()
                print("\n[+] New Connection Detected. \nListening from IP :",http_cli_addr[0]," \t\tThrough Port     :",http_cli_addr[1])
                # print(http_cli_sock.recv(2048).decode("utf-8"))                               
                g_data = http_cli_sock.recv(2048).decode("utf-8")
                valid1="User-Agent"
                ind = g_data.index(valid1)

                key_1 = ["OPR" , "Edg" , "Brave"] 
                key_2 = ["Windows" , "Linux" , "Android"]
                key_3 = "Firefox"

                if valid1 in g_data:
                    fla = True
                    print("The browser       : ",end="")
                    if "Chrome" in g_data : 
                        for i in key_1:
                            if i in g_data:
                                fla = False
                                if i == "OPR":
                                    print("Opera Group",end="")
                                elif i == "Edg":
                                    print("Edge",end="")
                    if fla == False:
                        pass
                    elif "Chrome" in g_data :
                        print("Chrome",end="")
                    if key_3 in g_data :
                        print("Firefox",end="")
                    print("\t\tOperating system : ",end="")
                    if "Wind" in g_data:
                        print(key_2[0])
                    elif "Linux" in g_data:
                        if key_2[2] in g_data:
                            print("Mobile/Emulator")
                        else:
                            print("Linux Machine")
                http_cli_sock.send(web_data)
                http_cli_sock.close()
                
    except KeyboardInterrupt:
        http_serv_sock.close()
        print("[!] Server powered off (Invoked Ctrl+c)")
        print("To main menu..")
    except sc.error as e:
        print(f"[!] Socket error: {e}")    
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
    finally:
        http_serv_sock.close()
        # print("Bye")

class SSH_Interface(pk.ServerInterface):
    def check_auth_password(self, username: str, password: str) -> int:
        print("Username :",username,"\tPassword :",password)
        return pk.AUTH_FAILED
    
    def check_auth_publickey(self, username: str, key: pk.PKey) -> int:
        return pk.AUTH_FAILED

def SSH_Pot():
    printer(me_who_loves_getting)
    # print("SSH honeypot")
    global IP,Queue,Soc
    defaults(999)
    des(999)
    def socketer(ssh_cli_sock , serv_key):
        con = pk.Transport(ssh_cli_sock)
        con.add_server_key(serv_key)
        con.start_server(server=SSH_Interface())
        # ssh_cli_sock.close()
    try:
        ssh_serv_sock = sc.socket(sc.AF_INET,sc.SOCK_STREAM)
        # ssh_serv_sock.setsockopt(sc.SOL_SOCKET,sc.SO_RCVBUF,2**16)
        ssh_serv_sock.bind((IP,Soc))
        ssh_serv_sock.listen(400)
        serv_key = pk.RSAKey.from_private_key_file('key')
        print(f"\nSSH server is up active in {IP} , try connecting using ssh command in CMD/Terminal .\nThe Username and Password used will be listed , \n")

        while True:
            try :
                readable = select.select([ssh_serv_sock],[],[],0.1)
                if ssh_serv_sock in readable[0]: 
                    ssh_cli_sock , ssh_cli_addr = ssh_serv_sock.accept()
                    print("[+] New Connection Detected. Listening from IP :",ssh_cli_addr[0]," through Port :",ssh_cli_addr[1],"\n")
                    Th = threading.Thread(target=socketer,args=(ssh_cli_sock,serv_key))
                    Th.start()
            except sc.error as e :
                print(f"[!] Socket error: {e}")
            except pk.SSHException as e:
                logging.error(f"SSH Exception in socketer: {e}")
            except Exception as e:  
                logging.error(f"General Exception in socketer: {e}")
            
    except KeyboardInterrupt :
        ssh_serv_sock.close()
        print("[!] Server powered off (Invoked Ctrl+c)")
        print("To main menu..")
    except sc.error as e:
        print(f"[!] Socket error: {e}")    
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
    finally:
        ssh_serv_sock.close()
        # print("Bye")

#x-----------------------------------------------------------------------------------------------------------------------------------------------------------x#

start()
while True:
    try:
        load()
        print("\nThanks for using our honeypot project, built specifically for local network.!")
        time.sleep(0.1)
        print("Choose the apropriate service to deploy honeypot on...")
        load()
        print("[1] HTTP")
        print("[2] SSH")
        print("[0] Exit")
        print("!note: only enter the option number.")
        inp = input()
        if len(inp)>=1:
            if inp[0] == '1':
                load()
                HTTP_Pot()
            elif inp[0] == '2':
                load()
                SSH_Pot()
            elif inp[0] == '0' or inp.lower()[0]=='e':
                print("Done getting out!")
                break
            else:
                print("Invalid option, read the options listed and choose wisely")
    except KeyboardInterrupt :
        # print("Keyboard Invoked Exiting!")
        print("Done getting out!")
        break
