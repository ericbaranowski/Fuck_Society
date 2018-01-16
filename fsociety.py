# Author: Not_Found_Error
# Non dovresti essere qui :O

import os, sys, time, readline, signal, socket, requests, datetime, random
from time import sleep
import platform # cat os
import urllib2, json # Geo-Location
import struct # get gateway (+socket)
import re, uuid # get mac address
import argparse

reload(sys)
sys.setdefaultencoding('utf8') # for raw input ansi/unicode

skull = u"\u2620"
biohazard = u"\u2623"
# Titolo terminale
sys.stdout.write("\x1b]2;" + biohazard + " Fuck Society " + biohazard + "\x07")

global end, white, red, blue, green, dark_gray, bright_green, bright_cyan, bright_yellow, underline, Tools
end = '\033[0m'
white = '\033[1;37m'
red = '\033[1;31m'
blue = '\033[1;34m'
green = '\033[0;32m'
dark_gray = '\033[1;30m'
bright_green = '\033[1;32m'
bright_cyan = '\033[1;36m'
bright_yellow = '\033[1;33m'
#
underline = '\033[4m'
Tools = "125 Tools"

if sys.version_info.major >= 2.7:
    print("\n[ {}Attenzione{} ]: Questa versione non e' supportata dal tuo sistema.".format(bright_yellow, end))
    print("[>] Esegui {}installer.py{} per installare tutto il necessario.\n".format(bright_green, end))
    sys.exit()

euid = os.geteuid()
if euid != 0:
    print("[ {}Attenzione{} ]: Per proseguire sono necessari i permessi di root.".format(bright_yellow,end))
    time.sleep(.5)
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    # the next line replaces the currently-running process with the sudo
    os.execlpe('sudo', *args)

# Verifica se eseguito installer.py
try:
    import netifaces,paramiko
except ImportError:
    print("")
    print("[{} Attenzione {}]: Esegui {}installer.py{} per avviare il programma.".format(bright_yellow,end,red, end))
    print("")
    sys.exit()
try:
    installer_done = open("Tools/Complete.txt")
except IOError:
    print("")
    print("[{} Attenzione {}]: Esegui {}installer.py{} per usare il programma.".format(bright_yellow,end,red, end))
    print("")
    sys.exit()

def get_gateway():
    with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
#
def menu():
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=28, cols=91))
    sys.stdout.write(end)
    class MyCompleter(object):  # Custom completer
        def __init__(self, options):
            self.options = sorted(options)
        def complete(self, text, state):
            if state == 0:  # on first trigger, build possible matches
                if text:  # cache matches (entries that start with entered text)
                    self.matches = [s for s in self.options
                                        if s and s.startswith(text)]
                else:  # no text entered, all matches possible
                    self.matches = self.options[:]
            # return match indexed by state
            try:
                return self.matches[state]
            except IndexError:
                return None
    completer = MyCompleter([
    # Comandi - unica categoria
    "apt", "torghost","start","stop", "os", "shutdown", "reboot", "help", "info", "updatedb", "repo", "update",
    "ifconfig", "macchanger", "anOFF", "anON", "msfconsole", "ftp","unbug", "net_restart","mapscii",
    "restart", "reload", "kill", "quit", "exit","ping",
    # Nmap
    "nmap","local","dlocal","web","os","netdiscover","dweb",
    # Gathering
    "geoip", "whois", "maltego", "sn1per", "red_hawk", "ktfconsole", "operativef", "dmitry", "inspy","credmap","theharvester",
    # WebApp
    "xerxes", "ufonet", "zambie", "goldeneye","recon-ng","sslscan","ipmipwn","xsstracer","fbht","pybomber","whatweb","commix","onioff","joomscan",
    "sqlmap","scan","inj", "sqliv","dork","web","jaidam","sshscan","pentmenu","a2sv","crips","vbscan","torshammer","siege","brutesploit",
    "cpscan","dtect", "dracnmap", "sechub", "arachni", "wpscan", "zaproxy", "zenmap", "uniscan", "droopescan", "striker","instarecon","dsxs",
    "hydra","ftp", "xhydra", "tulpar", "bingoo","xattacker", "knockmail", "osrframework","blazy", "xsssniper","sublist3r","urlextractor",
    # WiFi
    "airgeddon", "wifite", "fakeauth", "fluxion", "wifiphisher",
    "routersploit", "wirespy", "wpsbreaker", "netattack",
    # MitM
    "bettercap", "morpheus", "wireshark", "ettercap", "mitmf","mitmap",
    # Exploiting
    "chaos", "overthruster", "arcanus", "evildroid", "ezsploit", "zirikatu","astroid","kautilya","termineter","wifijammer",
    "armitage", "setoolkit", "fatrat", "eggshell", "shellsploit", "saint","koadic","pentestly","debinject","cisco-ge","patator",
    "beelogger","brutal","jexboss","weeman","androidpincrack","u3-pwn", "ngrok","l0l","extract-hash","kayak","ioscrack","cheetah",
    # MultiTool
    "hakkuf","pythem","trity","penbox","bluebox-ng","simple-ducky","discover","zarp","sb0x","atscan",
    # Others
    "printerspam", "httrack"
    ])
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')

    # input
    try:
        command_input = raw_input("[FS]:")
    except (KeyboardInterrupt, EOFError):
        print("\n[ {}Attenzione{} ]: Usa {}exit{} o {}quit{} per uscire.".format(bright_yellow,end, blue,end, blue,end))
        return menu()
    tokens = command_input.split()
    try:
        command = tokens[0]
    except IndexError:
        command = None
    try:
        option = tokens[1]
    except IndexError:
        option = None
    try:
        argument = tokens[2]
    except IndexError:
        argument = None
    try:
        argument2 = tokens[3]
    except IndexError:
        argument2 = None
    try:
        argument3 = tokens[4]
    except IndexError:
        argument3 = None
    try:
        argument4 = tokens[5]
    except IndexError:
        argument4 = None
    try:
        argument5 = tokens[6]
    except IndexError:
        argument5 = None
    try:
        argument6 = tokens[7]
    except IndexError:
        argument6 = None
    try:
        argument7 = tokens[8]
    except IndexError:
        argument7 = None
    try:
        argument8 = tokens[9]
    except IndexError:
        argument8 = None
    args = tokens[1:]

    # comandi tecnici
    if command == 'help' or command == '?':
        help()
    elif command == 'info':
        info()
    elif command == 'clear' or command == 'reset':
        os.system(command)
        return menu()
    elif command == 'logo' or command == 'banner':
        logo_menu()

    # comandi di sistema
    elif command == 'restart':
        print("[*] Riavvio fsociety")
        time.sleep(1)
        sys.stdout.write("[*] Fermo i servizi ")
        sys.stdout.flush()
        os.system("service postgresql stop && echo 0 > /proc/sys/net/ipv4/ip_forward && service apache2 stop")
        sys.stdout.write("[ {}DONE{} ]\n".format(bright_green,end))
        sys.stdout.flush()
        time.sleep(1)
        os.system("echo 'file destinato al macello' > Logs/verify_first_boot.txt") # verifica primo avvio
        logo_menu()
    elif command == 'reload':
        sys.stdout.write("[*] Ricarico i servizi ")
        sys.stdout.flush()
        os.system("service postgresql restart && echo 1 > /proc/sys/net/ipv4/ip_forward && service apache2 restart")
        sys.stdout.write("[ {}DONE{} ]\n".format(bright_green,end))
        sys.stdout.flush()
        return menu()
    elif command == 'kill':
        sys.stdout.write("[*] Fermo i servizi ")
        sys.stdout.flush()
        os.system("service postgresql stop && echo 0 > /proc/sys/net/ipv4/ip_forward && service apache2 stop")
        sys.stdout.write("[ {}DONE{} ]\n".format(bright_green,end))
        sys.stdout.flush()
        return menu()
    elif command == 'exit' or command == 'quit':
        exit()
    #
    elif command == 'apt':
        if option == 'reboot':
            os.system("xterm -T 'Updating...' -e 'apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'")
            os.system("reboot")
        elif option == 'shutdown':
            if argument == 'now':
                os.system("xterm -T 'Updating...' -e 'apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'")
                os.system("shutdown now")
            os.system("xterm -T 'Updating...' -e 'apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'")
            os.system("shutdown")
            return menu()
        sys.stdout.write("[*] Aggiorno ")
        sys.stdout.flush()
        os.system("xterm -T 'Updating...' -e 'apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'")
        sys.stdout.write("[ {}DONE{} ]\n".format(bright_green,end))
        sys.stdout.flush()
        return menu()
    elif command == 'updatedb':
        os.system("updatedb")
        print("[ {}OK{} ] Database aggiornato.".format(bright_green,end))
        return menu()
    elif command == 'os':
        if option:
            if argument:
                if argument2:
                    if argument3:
                        if argument4:
                            if argument5:
                                if argument6:
                                    if argument7:
                                        if argument8:
                                            os.system("{} {} {} {} {} {} {} {} {}".format(option,argument,argument2,argument3,argument4,argument5,argument6,argument7,argument8))
                                            return menu()
                                        os.system("{} {} {} {} {} {} {} {}".format(option,argument,argument2,argument3,argument4,argument5,argument6,argument7))
                                        return menu()
                                    os.system("{} {} {} {} {} {} {}".format(option,argument,argument2,argument3,argument4,argument5,argument6))
                                    return menu()
                                os.system("{} {} {} {} {} {}".format(option,argument,argument2,argument3,argument4,argument5))
                                return menu()
                            os.system("{} {} {} {} {}".format(option,argument,argument2,argument3,argument4))
                            return menu()
                        os.system("{} {} {} {}".format(option,argument,argument2,argument3))
                        return menu()
                    os.system("{} {} {}".format(option,argument,argument2))
                    return menu()
                os.system("{} {}".format(option,argument))
                return menu()
            os.system("{}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}os{} richiede un comando qualunque (massimo 9 argomenti).".format(red,end, blue,end))
        return menu()

    elif command == 'repo':
        if option == 'update':
            sources_list_update = """
deb https://http.kali.org/kali kali-rolling main non-free contrib
deb-src https://http.kali.org/kali kali-rolling main non-free contrib
deb http://repo.kali.org/kali kali-rolling main non-free contrib
deb-src https://repo.kali.org/kali kali-rolling main non-free contrib"""
            os.system('echo "{}" > /etc/apt/sources.list'.format(sources_list_update))
            print("[ {}Attenzione{} ]: File {}sources.list{} aggiornato. ({}/etc/apt/sources.list{})".format(bright_yellow, end,blue, end, blue, end))
            print("[>] Digita {}apt{} per aggiornare il sistema.".format(blue, end))
        else:
            print("[ {}Errore{} ]: Scelta non valida. Usa {}help{} in caso di panico.".format(red,end, blue,end))
        return menu()

    elif command == 'net_restart':
        os.system("service network-manager restart")
        print("[ {}OK{} ] Servizio {}network-manager{} riavviato.".format(bright_green,end, blue,end))
        return menu()
    elif command == 'service':
        if option:
            if argument == 'start' or argument == 'restart' or argument == 'stop' or argument == 'reload':
                return menu()
            else:
                print("[ {}Errore{} ]: {}service{} richiede un opzione.".format(red,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}service{} richiede un servizio e un opzione.".format(red,end, blue,end))
        return menu()

    elif command == 'ifconfig':
        if option:
            if argument:
                os.system("ifconfig {} {}".format(option,argument))
                return menu()
            os.system("ifconfig {}".format(option))
            return menu()
        try:
            print("---] Interface    :  " + blue + netifaces.gateways()['default'][netifaces.AF_INET][1] + end)
        except KeyError:
            print("---] Interface    :  " + blue + "Nessuna Interfaccia Connessa" + end)
        try:
            print("---] Local IP     :  " + blue + [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0] + end)
        except socket.error:
            print("---] Local IP     :  " + blue + "Nessuna Connessione" + end)
        print("---] Mac Address  :  " + blue + ':'.join(re.findall('..', '%012x' % uuid.getnode())) + end)
        print("---] Gateway      :  " + blue + str(get_gateway()) + end)
        try:
            print("---] Public IP    :  " + blue + requests.get('http://ip.42.pl/raw').text + end)
        except requests.exceptions.ConnectionError:
            print("---] Public IP    :  " + blue + "Nessuna Connessione" + end)
        host = "8.8.8.8"
        port = 53
        timeout = 3
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            pass
        except Exception:
            print("[ {}Attenzione{} ]: Nessuna connessione a internet.".format(bright_yellow,end))
            print("[ {}Attenzione{} ]: Disattiva TorGhost o verifica la tua connessione.".format(bright_yellow,end))
        return menu()
    elif command == 'ping':
        if option:
            os.system("ping {}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Ping{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    # Spoofing
    elif command == 'macchanger' or command == 'mac':
        os.system("xterm -T 'Changing Mac Address...' -e 'ifconfig wlan0 down && ifconfig eth0 down && macchanger -r wlan0 && macchanger -r eth0 && ifconfig eth0 up && ifconfig wlan0 up && service network-manager restart'")
        print("[ {}OK{} ] Indirizzo MAC cambiato.".format(bright_green,end))
        return menu()
    elif command == 'torghost':
        if option == 'start':
            os.system("xterm -T 'TorGhost' -e 'torghost start'")
            print("[ {}OK{} ] TorGhost Avviato.".format(bright_green,end))
            return menu()
        elif option == 'stop':
            os.system("xterm -T 'TorGhost' -e 'torghost stop'")
            os.system('echo "nameserver 8.8.8.8" > /etc/resolv.conf')
            print("[ {}OK{} ] TorGhost Fermato.".format(bright_green,end))
            print("[ {}OK{} ] File {}resolv.conf{} ripristinato.".format(bright_green,end, blue,end))
            return menu()
        else:
            print("[ {}Errore{} ]: Argomenti non validi. Usa {}torghost start{} o {}torghost stop{}.".format(red,end, blue,end, blue,end))
            return menu()

    # Cracking
    elif command == 'androidpincrack':
        if option:
            if os.path.exists(option) == False:
                print("[ {}Errore{} ]: Directory o File non trovati.".format(red,end))
                return menu()
            if argument:
                os.system("cd Tools/AndroidPINCrack/ && python AndroidPINCrack.py -H {} -s {}".format(option, argument))
            else:
                print("[ {}Errore{} ]: {}AndroidPINCrack{} richiede un {}Salt Hash{}.".format(red,end, blue,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}AndroidPINCrack{} richiede il file {}*.key{} e un {}Salt Hash{}.".format(red,end, blue,end, blue,end, blue,end))
        return menu()
    elif command == 'extract-hash':
        if option:
            if os.path.exists(option) == False:
                print("[ {}Errore{} ]: File o Directory non trovati.".format(red,end))
                return menu()
            os.system("cd Tools/extract-hashes/ && python extract-hash.py {}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Extract-Hash{} richiede un file per l'estrazione.".format(red,end, blue,end))
            return menu()
    elif command == 'ioscrack':
        if option:
            if option == '-h':
                print("")
                print("[ {}Attenzione{} ]:".format(bright_yellow,end))
                print("  Se iTunes e' installato esegui il backup del dispositivo vittima con esso e avvia ")
                print("  ioscrack con {}ioscrack auto{}. ".format(blue,end))
                print("  Se iTunes non e' installato inserisci manualmente la cartella di backup con")
                print("  {}ioscrack /path/to/backup/folder{}.".format(blue,end))
                print("")
                print("[{}Comandi IosCrack{}]:".format(bright_green,end))
                print(" $ ioscrack  ")
                print("            auto                     : Cerca automaticamente la cartella di backup")
                print("            [path/to/backup/folder]  : Specifica la cartella di backup")
                print("")
                return menu()
            elif option == 'auto':
                os.system("cd Tools/iOSRestrictionBruteForce/ && python ioscrack.py -a -v")
                print("")
                return menu()
            if 'auto' not in option:
                os.system("cd Tools/iOSRestrictionBruteForce/ && python ioscrack.py -b {} -v".format(option))
                print("")
                return menu()
        else:
            print("[ {}Errore{} ]: {}IosCrack{} richiede un opzione valida. Digita {}ioscrack -h{} per ulteriori comandi.".format(red,end, blue,end, blue,end))
            return menu()
    elif command == 'patator':
        if option: # 1
            # 2
            if option == '-h':
                print("")
                print("[{}Comandi Patator{}]:".format(bright_green,end))
                print(" Come usarlo:                $ patator [modulo] <host> [user/email/password_file]")
                print(" Informazioni su un modulo:  $ patator [modulo] -h ")
                print("")
                print("[{}Moduli{}]:".format(bright_green,end))
                print("[ ssh / ftp / telnet / smtp / http / mysql / vnc ]")
                print("")
                return menu()
            elif option == 'ssh':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}SSH{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator ssh <host> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if os.path.exists(argument2) == False:
                            print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                            return menu()
                        os.system("patator ssh_login host={} password=FILE0 0={}".format(argument, argument2))
                        return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}ssh{}. Digita {}patator ssh -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}ssh{}. Digita {}patator ssh -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'ftp':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}FTP{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator ftp <host> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if os.path.exists(argument2) == False:
                            print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                            return menu()
                        os.system("patator ftp_login host={} password=FILE0 0={}".format(argument, argument2))
                        return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}ftp{}. Digita {}patator ftp -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}ftp{}. Digita {}patator ftp -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'telnet':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}Telnet{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator telnet <host> <user> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if argument3:
                            if os.path.exists(argument3) == False:
                                print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                                return menu()
                            os.system("patator telnet_login host={} inputs='{}\nFILE0' 0={}".format(argument, argument2, argument3))
                            return menu()
                        else: # argument3
                            print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}telnet{}. Digita {}patator telnet -h{} per aiuto.".format(red,end, blue,end, blue,end))
                            return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}telnet{}. Digita {}patator telnet -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}telnet{}. Digita {}patator telnet -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'smtp':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}SMTP{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator smtp <host> [user/email] <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if argument3:
                            if os.path.exists(argument3) == False:
                                print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                                return menu()
                            os.system("patator smtp_login host={} user={} password=FILE0 0={}".format(argument, argument2, argument3))
                            return menu()
                        else: # argument3
                            print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}SMTP{}. Digita {}patator smtp -h{} per aiuto.".format(red,end, blue,end, blue,end))
                            return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}SMTP{}. Digita {}patator smtp -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}SMTP{}. Digita {}patator smtp -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'http':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}HTTP{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator http <host> <user> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if argument3:
                            if os.path.exists(argument3) == False:
                                print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                                return menu()
                            os.system("patator http_fuzz url={} user_pass={}:FILE0 0={}".format(argument, argument2, argument3))
                            return menu()
                        else: # argument3
                            print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}HTTP{}. Digita {}patator http -h{} per aiuto.".format(red,end, blue,end, blue,end))
                            return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}HTTP{}. Digita {}patator http -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}HTTP{}. Digita {}patator http -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'mysql':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}MySql{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator mysql <host> <user> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if argument3:
                            if os.path.exists(argument3) == False:
                                print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                                return menu()
                            os.system("patator mysql_login host={} user={} password=FILE0 0={}")
                            return menu()
                        else: # argument3
                            print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}MySql{}. Digita {}patator mysql -h{} per aiuto.".format(red,end, blue,end, blue,end))
                            return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}MySql{}. Digita {}patator mysql -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}MySql{}. Digita {}patator mysql -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            elif option == 'vnc':
                if argument:
                    if argument == '-h':
                        print("")
                        print("[{}Patator{}-{}VNC{}]:".format(bright_green,end, bright_green,end))
                        print(" Come usarlo:  $ patator vnc <host> <path/to/wordlist.txt>")
                        print("")
                        return menu()
                    if argument2:
                        if os.path.exists(argument2) == False:
                            print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument2,end))
                            return menu()
                        os.system("patator vnc_login host={} password=FILE0 0={}".format(argument, argument2))
                        return menu()
                    else: # argument -h
                        print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}VNC{}. Digita {}patator vnc -h{} per aiuto.".format(red,end, blue,end, blue,end))
                        return menu()
                else:
                    print("[ {}Errore{} ]: Argomenti mancanti per il modulo {}VNC{}. Digita {}patator vnc -h{} per aiuto.".format(red,end, blue,end, blue,end))
                    return menu()
            ###
            else: # if option (2)
                print("[ {}Errore{} ]: {}Patator{} richiede un modulo valido. Digita {}patator -h{} per i comandi.".format(red,end, blue,end, blue,end))
                return menu()
        else: # if option (1)
            print("[ {}Errore{} ]: {}Patator{} richiede una serie di argomenti validi. Digita {}patator -h{} per aiuto.".format(red,end, blue,end, blue,end))
            return menu()
    elif command == 'cheetah':
        if option:
            if option == '-h':
                print("")
                print("[{}Comandi Aggiuntivi Cheetah{} ({}http bruteforce{})]:".format(bright_green,end, bright_green,end))
                print(" Come usarlo: $ cheetah <host> [path/to/wordlist.txt]")
                print("")
                print("[ {}Attenzione{} ]: Se desideri usare una wordlist diversa da quella di default di Cheetah,".format(bright_yellow,end))
                print("                inseriscila dopo l'indirizzo come nell'esempio d'uso qui sopra.")
                print("")
                return menu()
            if argument:
                if os.path.exists(argument) == False:
                    print("[ {}Errore{} ]: Wordlist {}{}{} non trovata.".format(red,end, blue,argument,end))
                    return menu()
                os.system("cd Tools/cheetah/ && python cheetah.py -u {} -p {}".format(option,argument))
                print("")
                return menu()
            os.system("cd Tools/cheetah/ && python cheetah.py -u {}".format(option))
            print("")
            return menu()
        else:
            print("[ {}Errore{} ]: {}Cheetah{} richiede un indirizzo. Digita {}cheetah -h{} per ulteriori comandi.".format(red,end, blue,end, blue,end))
            return menu()

    # Sistema
    elif command == 'shutdown':
        if option == 'now':
            os.system("shutdown now")
        elif option == '-c':
            os.system("shutdown -c")
            return menu()
        os.system("shutdown")
        return menu()
    elif command == 'reboot':
        os.system("reboot")
        return menu()
    elif command == 'msfconsole' or command == 'msf':
		os.system("gnome-terminal -- msfconsole")
		return menu()
    elif command == 'ftp':
        os.system("gnome-terminal -- ftp")
        return menu()
    elif command == 'unbug':
        os.system("xterm -T 'unbug' -e 'airmon-ng check kill && airodump-ng stop wlan0mon && airmon-ng stop eth0mon && ifconfig wlan0 down && ifconfig eth0 down && macchanger -r wlan0 && macchanger -r eth0 && ifconfig wlan0 up && ifconfig eth0 up && service network-manager restart'")
        os.system('echo "nameserver 8.8.8.8" > /etc/resolv.conf')
        print("[ {}OK{} ] Unbug completato.".format(bright_green,end))
        return menu()
    elif command == 'mapscii':
        os.system("telnet mapscii.me")
        logo_menu()

    # Scanning
    elif command == 'nmap':
        if option == None: # Cancella ELSE > questo if e' piu' importante della tua vita caro lettore :)
            print("[ {}Errore{} ]: {}Nmap{} richiede un opzione valida. Digita {}nmap -h{} per ulteriori informazioni.".format(red,end, blue,end, blue,end))
            return menu()
        elif option == 'local':
            os.system("nmap -sn 192.168.1.0/24")
            return menu()
        elif option == 'dlocal':
            os.system("nmap nmap -sV -T4 -F 192.168.1.0/24")
            return menu()
        elif option == 'web':
            if argument:
                os.system("nmap {}".format(argument))
                return menu()
            else:
                print("[ {}Errore{} ]: {}Nmap{} richiede un indirizzo.".format(red,end, blue,end))
                return menu()
        elif option == 'dweb':
            if argument:
                os.system("nmap -O -F -A -sN {}".format(argument))
                return menu()
            else:
                print("[ {}Errore{} ]: {}Nmap{} richiede un indirizzo.".format(red,end, blue,end))
                return menu()
        elif option == 'os':
            if argument:
                os.system("nmap -O {}".format(argument))
                return menu()
            else:
                print("[ {}Errore{} ]: {}Nmap{} richiede un indirizzo.".format(red,end, blue,end))
                return menu()
        elif option == '-h':
            print("")
            print(" [{}Comandi Nmap{}]:                                      ".format(bright_green, end))
            print("                                                          ")
            print("  $ nmap                                                  ")
            print("         local    : Scansione rapida locale               ")
            print("         dlocal   : Scansione dettagliata locale          ")
            print("         web *    : Scansione sito internet               ")
            print("         dweb *   : Scansione dettagliata sito internet   ")
            print("         os *     : Scansione dispositivo locale          ")
            print("         [custom] : Comando che vuoi (massimo 5 argomenti)")
            print("")
            return menu()
        elif option != 'local' or option != 'dlocal' or option != 'web' or option != 'os' or option != '-h':
            if argument:
                if argument2:
                    if argument3:
                        if argument4:
                            os.system("nmap {} {} {} {} {}".format(option, argument, argument2, argument3, argument4))
                            return menu()
                        os.system("nmap {} {} {} {}".format(option, argument, argument2, argument3))
                        return menu()
                    os.system("nmap {} {} {}".format(option, argument, argument2))
                    return menu()
                os.system("nmap {} {}".format(option, argument))
                return menu()
            os.system("nmap {}".format(option))
            return menu()
    elif command == 'netdiscover':
        os.system("netdiscover -p")
        return menu()

    # Gathering
    elif command == 'geoip':
        if option:
            ip1=option
            try:
                try:
                    url = "http://ip-api.com/json/"
                    response = urllib2.urlopen(url + ip1)
                    data = response.read()
                    values = json.loads(data)
                    print("")
                    print("IP              :  " + blue + values['query'] + end)
                    print("Stato           :  " + blue + values['status'] + end)
                    try:
                        print("Regione         :  " + blue + values['regionName'] + end)
                        print("Nazione         :  " + blue + values['country'] + end)
                        print("Citta'          :  " + blue + values['city'] + end)
                        print("Provider:       :  " + blue + values['isp'] + end)
                        print("Lat. / Long.    :  " + blue + str(values['lat']) + " / " + str(values['lon']) + end)
                        print("Codice Postale  :  " + blue + values['zip'] + end)
                        print("Fuso orario     :  " + blue + values['timezone'] + end)
                        print("Gestore         :  " + blue + values['as'] + end)
                        print("Google Maps     :  {}https://www.google.com/maps/search/?api=1&query={},{}{}".format(blue, str(values['lat']), str(values['lon']), end))
                        print("")
                        return menu()
                    except KeyError:
                        print("")
                        return menu()
                except socket.timeout:
                    print("[ {}Attenzione{} ]: Nessuna connessione a internet.".format(bright_yellow,end))
                    print("[ {}Attenzione{} ]: Disattiva {}TorGhost{} o verifica la tua connessione.".format(bright_yellow,end,blue,end))
                    return menu()
            except urllib2.URLError:
                print("[ {}Attenzione{} ]: Nessuna connessione a internet.".format(bright_yellow,end))
                print("[ {}Attenzione{} ]: Disattiva {}TorGhost{} o verifica la tua connessione.".format(bright_yellow,end,blue,end))
                return menu()
        else:
            print("[ {}Errore{} ]: {}Geoip{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'whois':
        if option:
            os.system("whois -H {}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Whois{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'maltego':
        os.system("gnome-terminal -- maltego")
        return menu()
    elif command == 'sn1per':
        if option:
            os.system("cd Tools/Sn1per/ && ./sniper {}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Sn1per{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'dmitry':
        if option:
            os.system("dmitry {} -i -w -s -e -p -o Logs/dmitry_log".format(option))
            print("\n[>] Informazioni salvate in {}Logs/dmitry_log.txt{}".format(blue,end))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Dmitry{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'red_hawk' or command_input == 'red hawk':
        os.system("gnome-terminal -- " + "php " + os.getcwd() + "/Tools/RED_HAWK/rhawk.php")
        return menu()
    elif command == 'ktfconsole' or command == 'ktf':
        os.system("gnome-terminal -- ktf.console")
        return menu()
    elif command == 'operativef' or command == 'operative':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/operative-framework/operative.py")
        return menu()
    elif command == 'inspy':
        if option:
            if argument:
                job_list = option.split()
                print("")
                for elements in job_list:
                    os.system('echo "{}" > Logs/inspy.txt'.format(elements))
                    print("Ricerca: [{}{}{}]".format(blue,elements,end))
                os.system("inspy --empspy Logs/inspy.txt {}".format(argument))
                os.system("rm Logs/inspy.txt")
                print("")
                return menu()
            else:
                print("[ {}Errore{} ]: {}Inspy{} richiede un {}Luogo{}.".format(red,end, blue,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}Inspy{} richiede un {}Mestiere{} ed un {}Luogo{}.".format(red,end, blue,end, blue,end, blue,end))
        return menu()
    elif command == 'tulpar':
        tulpar_startup()
    elif command == 'osrframework':
        os.system("gnome-terminal -- osrfconsole.py")
        return menu()
    elif command == 'credmap':
        if option:
            os.system("cd Tools/credmap && python credmap.py --email {}".format(option))
        else:
            print("[ {}Errore{} ]: {}Credmap{} richiede un {}username{} o un {}indirizzo email{}.".format(red,end, blue,end, blue,end, blue,end))
        return menu()
    elif command == 'theharvester':
        if option:
            if 'www.' in option or 'http' in option or 'https' in option:
                print("[ {}Errore{} ]: {}TheHarvester{} richiede un indirizzo senza {}www{}, {}http{} o {}https{} (es: example.com).".format(red,end, blue,end, blue,end, blue,end, blue,end))
                return menu()
            os.system("theharvester -d {} -b all -v -n -t".format(option))
        else:
            print("[ {}Errore{} ]: {}TheHarvester{} richiede un indirizzo.".format(red,end, blue,end))
        print("")
        return menu()

    # WebApp
    elif command == 'ipmipwn':
        if option:
            os.system("cd Tools/IPMIPWN/ && python ipmipwn.py {}".format(option))
            return menu()
        else:
            print("[ {}Attenzione{} ]: Assicurati che l'host abbia la porta 623 aperta. Questo tool utilizza la ".format(bright_yellow,end))
            print("                vulnerabilita' 'Cipher 0' per il bypass dell'autenticazione.")
            print("")
            print("[ {}Errore{} ]: {}Ipmipwn{} richiede un indirizzo.".format(red,end, blue, end))
            return menu()
        # DDoS
    elif command == 'xerxes':
        if option:
            os.system("xterm -T 'Xerxes' -e './Tools/xerxes/xerxes {} 80'".format(option))
        else:
            print("[ {}Errore{} ]: {}Xerxes{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'ufonet':
        os.system("xterm -T 'UfoNet' -e 'cd Tools/ufonet/ && ./ufonet --download-zombies'")
        time.sleep(.02)
        os.system("xterm -T 'UfoNet Logs' -e 'cd Tools/ufonet/ && ./ufonet --gui'")
        return menu()
    elif command == 'zambie':
        os.system("cd Tools/zambie/ && python zambie.py")
        logo_menu()
    elif command == 'goldeneye':
        if option:
            if 'http' in option or 'https' in option:
                os.system("xterm -T 'Goldeneye' -e 'goldeneye {} -w 25 -s 1000 -d'".format(option))
                return menu()
            else:
                print("[ {}Errore{} ]: {}Goldeneye{} richiede un indirizzo con {}http{} o {}https{}.".format(red,end, blue,end, blue,end, blue,end))
                return menu()
        else:
            print("[ {}Errore{} ]: {}Goldeneye{} richiede un indirizzo con {}http{} o {}https{}.".format(red,end, blue,end, blue,end, blue,end))
            return menu()
    elif command == 'torshammer':
        if option:
            os.system("xterm -T 'TorShammer' -e 'python Tools/torshammer/torshammer.py -t {}'".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Torshammer{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()

        #injection
    elif command == 'sqlmap':
        if option == 'scan':
            if argument:
                os.system("sqlmap -g {}".format(argument))
            else:
                print("[ {}Errore{} ]: {}Sqlmap{} richiede un indirizzo.".format(red,end, blue,end))
        elif option == 'inj':
            sqlmap_startup()
        else:
            print("[ {}Errore{} ]: {}Sqlmap{} richiede un opzione valida.".format(red,end, blue,end))
        return menu()
    elif command == 'sqliv':
        if option == 'dork':
            if argument:
                os.system("python Tools/sqliv/sqliv.py -e google -d {} -p 20".format(argument))
                os.system("xterm -T 'Moving...' -e 'rm Logs/searches.txt && mv searches.txt Logs/'")
            else:
                print("[ {}Errore{} ]: {}Sqliv{} richiede un indirizzo.".format(red,end, blue,end))
        elif option == 'web':
            if argument:
                os.system("python Tools/sqliv/sqliv.py -e google -t {} -p 20".format(argument))
            else:
                print("[ {}Errore{} ]: {}Sqliv{} richiede un indirizzo.".format(red,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}Sqliv{} richiede un opzione valida e un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'commix':
        if option:
            if option == '-h':
                print("")
                print(" [{}Comandi Commix Aggiuntivi{}]:".format(bright_green,end))
                print("  Uso: $ commix <indirizzo> [opzioni]")
                print("")
                print("  l3          : Usa livello 3 per l'injection (lento)")
                print("  shellshock  : Usa metodo shellshock per l'injection")
                print("")
                return menu()
            if argument == 'l3' and argument2 == 'shellshock' or argument == 'shellshock' and argument2 == 'l3':
                print("[ {}Errore{} ]: {}shellshock{} e {}l3{} non possono essere usati insieme.".format(red,end, blue,end, blue,end))
                return menu()
            elif argument == 'l3':
                os.system("commix -u {} --ignore-401 --random-agent --force-ssl --all --level=3".format(option))
                return menu()
            elif argument == 'shellshock':
                os.system("commix -u {} --ignore-401 --random-agent --force-ssl --all --shellshock".format(option))
                return menu()
            os.system("commix -u {} --ignore-401 --random-agent --force-ssl --all".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Commix{} richiede un indirizzo. Digita {}commix -h{} per ulteriori comandi.".format(red,end, blue,end, blue,end))
            return menu()

        # Scanning
    elif command == 'cpscan':
        if option:
            if '.' not in option:
                print("[ {}Errore{} ]: Inserisci un url valido.".format(red,end, blue,end))
                return menu()
            os.system("xterm -T 'Cpscan' -e 'cd Tools/cpscan/ && python cpscan.py -t {} -v'".format(option))
        else:
            print("[ {}Errore{} ]: {}Cpscan{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'dtect':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/D-TECT/d-tect.py")
        return menu()
    elif command == 'dracnmap':
        os.system("reset")
        os.system("./Tools/Dracnmap/dracnmap*.sh")
        logo_menu()
    elif command == 'sechub':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/secHub/sechub.py")
        return menu()
    elif command == 'arachni':
        if option:
            if 'http' in option or 'https' in option:
                print("[ {}Attenzione{} ]: Premi {}Ctrl + C{} per fermare la scansione.".format(bright_yellow,end, blue,end))
                print("[>] Piu' lunga la scansione, piu' info per te.\n")
                time.sleep(2)
                os.system("arachni {}".format(option))
                return menu()
            else:
                os.system("arachni http://{}".format(option))
                return menu()
        else:
            print("[ {}Errore{} ]: {}Arachni{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'wpscan':
        if option:
            os.system("wpscan {}".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Wpscan{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'zaproxy':
        os.system("xterm -T 'Zaproxy Logs' -e 'zaproxy'")
        return menu()
    elif command == 'zenmap':
        os.system("xterm -T 'Zenmap Logs' -e 'zenmap'")
        return menu()
    elif command == 'uniscan':
        if option:
            os.system("uniscan -u {} -qwedsg".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Uniscan{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'droopescan':
        droopescan_startup()
    elif command == 'bingoo':
        os.system("cd Tools/BinGoo/ && ./bingoo")
        logo_menu()
    elif command == 'knockmail':
        os.system("cd Tools/KnockMail/ && python knock.py")
        logo_menu()
    elif command == 'xsssniper':
        if option:
            os.system("cd Tools/xsssniper/ && python xsssniper.py -u {} --crawl".format(option))
        else:
            print("[ {}Errore{} ]: {}Xsssniper{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'striker':
        os.system("cd Tools/Striker/ && python striker.py")
        return menu()
    elif command == 'sublist3r':
        if option:
            os.system("sublist3r -d {} -p 80 -v".format(option))
        else:
            print("[ {}Errore{} ]: {}Sublist3r{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'jaidam':
        os.system("cd Tools/Jaidam/ && python jaidam.py")
        logo_menu()
    elif command == 'sshscan':
        if option:
            os.system("python Tools/SSHScan/sshscan.py -t {}".format(option))
            print("")
        else:
            print("[ {}Errore{} ]: {}SSHScan{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'pentmenu':
        os.system("./Tools/pentmenu/pentmenu")
        logo_menu()
    elif command == 'a2sv':
        if option:
            if 'https' in option:
                os.system("a2sv -t {} -p 443".format(option))
                return menu()
            if 'http' in option or 'http' not in option:
                os.system("a2sv -t {} -p 80".format(option))
                return menu()
        else:
            print("[ {}Errore{} ]: {}A2SV{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'recon-ng':
        os.system("gnome-terminal -- recon-ng")
        return menu()
    elif command == 'sslscan':
        if option:
            if 'https' in option:
                os.system("sslscan {}:443".format(option))
                print("")
                return menu()
            if 'http' in option or 'http' not in option:
                os.system("sslscan {}:80".format(option))
                print("")
                return menu()
        else:
            print("[ {}Errore{} ]: {}Sslscan{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'xsstracer':
        if option:
            if 'https' in option:
                os.system("cd Tools/XSSTracer/ && python xsstracer.py {} 443".format(option))
                return menu()
            elif 'http' in option or 'http' not in option:
                os.system("cd Tools/XSSTracer/ && python xsstracer.py {} 80".format(option))
                return menu()
        else:
            print("[ {}Errore{} ]: {}XSSTracer{} richiede un indirizzo.".format(red, end, blue, end))
            return menu()
    elif command == 'crips':
        os.system("gnome-terminal -- crips")
        return menu()
    elif command == 'vbscan':
        if option:
            if 'https' in option:
                os.system("cd Tools/vbscan/ && perl vbscan.pl {}".format(option))
                return menu()
            if 'http' in option:
                os.system("cd Tools/vbscan/ && perl vbscan.pl {}".format(option))
                return menu()
            elif 'http' not in option:
                os.system("cd Tools/vbscan/ && perl vbscan.pl http://{}".format(option))
                return menu()
        else:
            print("[ {}Errore{} ]: {}Vbscan{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'whatweb':
        if option:
            os.system("whatweb -v -a 3 {}".format(option))
        else:
            print("[ {}Errore{} ]: {}WhatWeb{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'siege':
        if option:
            os.system("siege -g {}".format(option))
        else:
            print("[ {}Errore{} ]: {}Siege{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'urlextractor':
        if option:
            os.system("cd Tools/URLextractor/ && ./extractor.sh {}".format(option))
            print("")
        else:
            print("[ {}Errore{} ]: {}URLextractor{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'instarecon':
        if option:
            if 'www' in option or 'http' in option or 'https' in option:
                print("[ {}Errore{} ]: {}InstaRecon{} richiede un indirizzo senza {}www{}, {}http{} o {}https{} (es: example.com).".format(red,end, blue,end, blue,end, blue,end, blue,end))
                return menu()
            os.system("instarecon.py {}".format(option))
            print("")
            return menu()
        else:
            print("[ {}Errore{} ]: {}InstaRecon{} richiede un indirizzo senza {}www{}, {}http{} o {}https{} (es: example.com).".format(red,end, blue,end, blue,end, blue,end, blue,end))
            return menu()
    elif command == 'onioff':
        if option:
            if '.onion' not in option:
                print("[ {}Errore{} ]: {}Onioff{} richiede un indirizzo Tor valido.".format(red,end, blue,end))
                return menu()
            sys.stdout.write("[*] Avvio Tor")
            sys.stdout.flush()
            os.system("service tor start")
            sys.stdout.write("  [ {}DONE{} ]\n".format(bright_green,end))
            sys.stdout.flush()
            os.system("cd Tools/onioff/ && python onioff.py {}")
            sys.stdout.write("\n{}[*] Fermo Tor".format(end))
            sys.stdout.flush()
            os.system("service tor stop")
            sys.stdout.write("  [ {}DONE{} ]\n".format(bright_green,end))
            sys.stdout.flush()
            return menu()
        else:
            print("[ {}Errore{} ]: {}Onioff{} richiede un indirizzo Tor.".format(red,end, blue,end))
            return menu()
    elif command == 'dsxs':
        if option:
            print("")
            os.system("cd Tools/DSXS/ && python dsxs.py -u {}".format(option))
            print("")
            return menu()
        else:
            print("[ {}Errore{} ]: {}Dsxs{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()
    elif command == 'joomscan':
        if option:
            if option == '-h':
                print("")
                print("[{}Comandi Joomscan{}]:".format(bright_green,end))
                print(" Come usarlo:  $ joomscan <target> [options]")
                print("")
                print(" -nf  : No Firewall   - Nessun rilevamento del Firewall")
                print(" -nv  : No Version    - Nessun Rilevamento della versione")
                print(" -nvf : No V. & No F. - Nessun Rilevamento Firewall e Versione")
                print(" -vu  : Verbosity     - Mostra un output piu' verboso")
                print("")
                return menu()
            if argument:
                if argument2:
                    if argument3:
                        if argument4:
                            os.system("joomscan -u {} -sp {} {} {} {}".format(option, argument, argument2, argument3, argument4))
                            return menu()
                        os.system("joomscan -u {} -sp {} {} {}".format(option, argument, argument2, argument3))
                        return menu()
                    os.system("joomscan -u {} -sp {} {}".format(option, argument, argument2))
                    return menu()
                elif argument == '-nf' or argument == '-vu' or argument == '-nvf' or argument == '-nv':
                    os.system("joomscan -u {} -sp {}".format(option,argument))
                    return menu()
                else:
                    print("[ {}Errore{} ]: {}Joomscan{} richiede un opzione valida.".format(red,end, blue,end))
                    return menu()
            os.system("joomscan -u {} -sp".format(option))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Joomscan{} richiede un indirizzo. Digita {}joomscan -h{} per ulteriori comandi.".format(red,end, blue,end, blue,end))
            return menu()

    # BruteForce
    elif command == 'hydra':
        if option == 'ftp':
            if argument:
                if argument2:
                    if argument3:
                        if os.path.exists(argument3) == False:
                            print("[ {}Errore{} ]: Directory o File non trovati.".format(red,end))
                            return menu()
                        print("")
                        os.system("hydra -l {} -P {} ftp://ftp.{}".format(argument2, argument3, argument))
                        os.system("xterm -e 'mv hydra.restore Oth/'")
                    else:
                        print("[ {}Errore{} ]: {}Hydra Ftp{} richiede una wordlist.".format(red,end, blue,end))
                else:
                    print("[ {}Errore{} ]: {}Hydra Ftp{} richiede utente e wordlist.".format(red,end, blue,end))
            else:
                print("[ {}Errore{} ]: {}Hydra Ftp{} richiede indirizzo, utente e wordlist.".format(red,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}Hydra Ftp{} richiede opzione, indirizzo, utente e wordlist.".format(red,end, blue,end))
        return menu()
    elif command == 'xhydra':
        os.system("gnome-terminal -- xhydra")
        return menu()
    elif command == 'xattacker':
        os.system("reset")
        os.system("cd Tools/XAttacker/ && perl XAttacker.pl")
        logo_menu()
    elif command == 'blazy':
        os.system("cd Tools/Blazy && python blazy.py")
        return menu()
    elif command == 'fbht':
        os.system("cd Tools/fbht/ && python main.py") ; sleep(.1)
        logo_menu()
    elif command == 'brutesploit':
        os.system("cd Tools/BruteSploit/ && ./Brutesploit")
        logo_menu()

    # WiFi
        # Hacking
    elif command == 'airgeddon':
        os.system("reset")
        os.system("cd Tools/airgeddon/ && ./airgeddon.sh")
        logo_menu()
    elif command == 'fluxion':
        os.system("reset")
        os.system("cd Tools/fluxion/ && ./fluxion.sh")
        logo_menu()
    elif command == 'fakeauth':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/FakeAuth/FakeAuth/fakeauth.py")
        return menu()
    elif command == 'wifiphisher':
        if option:
            os.system("wifiphisher -nJ -e '{}' -T firmware-upgrade".format(option))
        else:
            print("[ {}Errore{} ]: {}Wifiphisher{} richiede un nome per creare un Fake Access Point.".format(red,end, blue,end))
        return menu()
    elif command == 'wifite':
        os.system("gnome-terminal -- wifite")
        return menu()
    elif command == 'wpsbreaker':
        os.system("cd Tools/HT-WPS-Breaker/ && ./HT-WB.sh")
        logo_menu()
    elif command == 'netattack':
        os.system("reset")
        os.system("cd Tools/netattack2/ && python netattack2.py")
        logo_menu()
    elif command == 'wifijammer':
        os.system("gnome-terminal -- python Tools/wifijammer/wifijammer.py")
        return menu()
        # Exploiting
    elif command == 'routersploit':
        os.system("reset")
        os.system("cd Tools/routersploit/ && python rsf.py")
        os.system("xterm -T 'Logs' -e 'rm routersploit.log'")
        logo_menu()
    elif command == 'wirespy':
        os.system("reset")
        os.system("cd Tools/wirespy/ && ./wirespy.sh")
        os.system("service apache2 start")
        logo_menu()

    # MitM
    elif command == 'bettercap':
        os.system("gnome-terminal -- bettercap -X -L -S ARP --proxy --proxy-https --httpd -O Logs/bettercap-saves.txt")
        print("[>] Logs al termine di Bettercap nella cartella del Tool in {}Logs/bettercap-saves.txt{}".format(blue,end))
        return menu()
    elif command == 'morpheus':
        os.system("reset")
        os.system("cd Tools/morpheus/ && ./morpheus.sh")
        logo_menu()
    elif command == 'wireshark':
        os.system("xterm -T 'Wireshark Logs' -e 'wireshark'")
        return menu()
    elif command == 'ettercap':
        os.system("xterm -T 'Ettercap Logs' -e 'ettercap -G'")
        return menu()
    elif command == 'mitmf':
        os.system("gnome-terminal -- mitmf -i {} --spoof --arp --dns --hsts --gateway {}".format(netifaces.gateways()['default'][netifaces.AF_INET][1], str(get_gateway())))
        return menu()
    elif command == 'mitmap':
        os.system("cd Tools/mitmAP/ && python3 mitmAP.py")
        print("[ {}Attenzione{} ]: Attendi per la riconnessione alla rete.".format(bright_yellow,end))
        time.sleep(3)
        logo_menu()

    # Exploiting
        # Payload Generator
    elif command == 'chaos':
        os.system("reset")
        os.system("cd Tools/CHAOS/ && go run CHAOS.go")
        logo_menu()
    elif command == 'overthruster':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/OverThruster/OverThruster.py")
        return menu()
    elif command == 'arcanus':
        os.system("reset")
        os.system("cd Tools/ARCANUS/ && ./ARCANUS")
        logo_menu()
    elif command == 'evildroid':
        os.system("reset")
        os.system("cd Tools/Evil-Droid/ && ./evil-droid")
        logo_menu()
    elif command == 'ezsploit':
        os.system("reset")
        os.system("cd Tools/ezsploit/ && ./ezsploit.sh")
        logo_menu()
    elif command == 'zirikatu':
        os.system("reset")
        os.system("cd Tools/zirikatu/ && ./zirikatu.sh")
        os.system("rm source/ output/ handler/ -r")
        logo_menu()
    elif command == 'kautilya':
        os.system("cd Tools/Kautilya/ && ruby kautilya.rb")
        logo_menu()
    elif command == 'debinject':
        os.system("cd Tools/Debinject/ && python debinject.py")
        logo_menu()
        # Exploiting
    elif command == 'armitage':
        os.system("gnome-terminal -- armitage")
        return menu()
    elif command == 'setoolkit' or command == 'set' or command == 's.e.t':
        os.system("gnome-terminal -- setoolkit")
        return menu()
    elif command == 'fatrat' or command == 'thefatrat':
        os.system("gnome-terminal -- fatrat")
        return menu()
    elif command == 'eggshell':
        os.system("reset")
        os.system("cd Tools/EggShell/ && python eggshell.py")
        logo_menu()
    elif command == 'shellsploit':
        os.system("gnome-terminal -- shellsploit")
        return menu()
    elif command == 'beelogger':
        os.system("cd Tools/BeeLogger/ && python bee.py")
        logo_menu()
    elif command == 'saint':
        os.system("cd Tools/sAINT/ && java -jar sAINT.jar")
        logo_menu()
    elif command == 'brutal':
        os.system("./Tools/Brutal/Brutal.sh")
        logo_menu()
    elif command == 'astroid':
        os.system("cd Tools/astroid/ && ./astroid.sh")
        logo_menu()
    elif command == 'jexboss':
        if option:
            os.system("cd Tools/jexboss/ && python jexboss.py -u {}".format(option))
        else:
            print("[ {}Errore{} ]: {}Jexboss{} richiede un indirizzo.".format(red,end, blue,end))
        return menu()
    elif command == 'weeman':
        os.system("reset")
        os.system("cd Tools/weeman/ && python weeman.py")
        logo_menu()
    elif command == 'u3-pwn':
        os.system("u3-pwn")
        logo_menu()
    elif command == 'koadic':
        os.system("cd Tools/koadic/ && ./koadic")
        logo_menu()
    elif command == 'pentestly':
        os.system("cd Tools/pentestly/ && ./pentestly")
        logo_menu()
    elif command == 'l0l':
        os.system("cd Tools/l0l/ && ./l0l")
        logo_menu()
    elif command == 'termineter':
        os.system("gnome-terminal -- termineter")
        return menu()
    elif command == 'kayak':
        os.system("gnome-terminal -- kayak")
        return menu()
    elif command == 'pybomber':
        print("")
        os.system("cd Tools/pybomber/ && python smsbomber.py")
        logo_menu()
    elif command == 'cisco-ge':
        if option:
            if argument:
                os.system("cd Tools/cisco-global-exploiter/ && perl cge.pl {} {}".format(option,argument))
                return menu()
            else:
                os.system("cd Tools/cisco-global-exploiter/ && perl cge.pl")
                print("\n[ {}Errore{} ]: {}Cisco-ge{} richiede un metodo d'attacco (1-14).".format(red,end, blue,end))
                return menu()
        else:
            os.system("cd Tools/cisco-global-exploiter/ && perl cge.pl")
            print("\n[ {}Errore{} ]: {}Cisco-ge{} richiede un bersaglio locale ed un metodo d'attacco (1-14).".format(red,end, blue,end))
            return menu()

    # MultiTool
    elif command == 'hakkuf' or command == 'hakku':
        os.system("reset")
        os.system("cd Tools/hakkuframework/ && ./hakku")
        logo_menu()
    elif command == 'trity':
        os.system("gnome-terminal -- trity")
        return menu()
    elif command == 'pythem':
        os.system("gnome-terminal -- pythem")
        return menu()
    elif command == 'penbox':
        os.system("gnome-terminal -- python " + os.getcwd() + "/Tools/PenBox/penbox.py")
        return menu()
    elif command == 'bluebox-ng':
        os.system("gnome-terminal -- bluebox-ng")
        return menu()
    elif command == 'simple-ducky':
        os.system("gnome-terminal -- simple-ducky")
        return menu()
    elif command == 'discover':
        os.system("cd Tools/discover/ && ./discover.sh")
        logo_menu()
    elif command == 'zarp':
        os.system("cd Tools/zarp/ && python zarp.py")
        logo_menu()
    elif command == 'sb0x':
        os.system("cd Tools/sb0x-project/ && python sb0x.py")
        logo_menu()
    elif command == 'atscan':
        os.system("cd Tools/ATSCAN/ && perl atscan.pl --interactive")
        logo_menu()

    # Others
    elif command == 'printerspam':
        print("")
        os.system("./Tools/printerspam.sh")
        print("")
        return menu()
    elif command == 'httrack':
        if option:
            os.system("gnome-terminal -- httrack {} -O Logs/httrack/{}/".format(option, option))
            print("[ {}Attenzione{} ]: Dati salvati nella cartella del Tool in {}Logs/httrack/{}/{}".format(bright_yellow,end,blue,option,end))
            return menu()
        else:
            print("[ {}Errore{} ]: {}Httrack{} richiede un indirizzo.".format(red,end, blue,end))
            return menu()

    # WAN
    elif command == 'ngrok':
        ngrok_srvc_list = ["tcp","http","tsl"]
        if option in ngrok_srvc_list:
            if int(argument) <= 0 or int(argument) > 65535:
                print("[ {}Errore{} ]: {}Ngrok{} richiede una porta valida. Cosa cazzo stai facendo?".format(red,end, blue,end))
                return menu()
            try:
                if int(argument):
                    os.system("gnome-terminal -- ngrok {} {}".format(option, argument))
            except TypeError:
                print("[ {}Errore{} ]: {}Ngrok{} richiede una porta.".format(red,end, blue,end))
            except ValueError:
                print("[ {}Errore{} ]: {}Ngrok{} richiede una porta, non qualche tua stronzata!".format(red,end, blue,end))
        else:
            print("[ {}Errore{} ]: {}Ngrok{} richiede un servizio valido e una porta da avviare come tunnel.".format(red,end, blue,end))
        return menu()

    # easter-egg :D
    elif command == 'fsociety':
        print("") ; sleep(1)
        print(" ---] 'Do you believe in your privacy?'") ; sleep(2)
        print(" ---] ~ 'Sure, why not?''") ; sleep(2)
        print(" ---] 'Why not? Because you are stupid.'") ; sleep(3)
        print("") ; sleep(1)
        return menu()
    elif command == 'fuck' or command == 'Fuck':
        if option == 'society' or option == 'Society':
            print("") ; sleep(1)
            print(" ---] 'Oh Elliot, it's Tyrell'") ; sleep(2)
            print(" ---] 'Tyrell it's Elliot'") ; sleep(2)
            print(" ---] 'This place is getting too small for all of us...'") ; sleep(3)
            print(" ---] ~ Mr.Robot") ; sleep(3)
            print("") ; sleep(.5)
            return menu()
        else:
            print("[ {}Manca un argomento...{} ]".format(bright_green,end))
            return menu()
    elif command == 'Not_Found_Error':
        print("")
        print("[   0.553991] Kernel panic - Unable to mount /root: Fatal exception") ; sleep(2)
        print("[   0.553060] 01000110 01110101 01100011 01101011 00100000 01010011 01101111")
        print("[   0.553060] 01100011 01101001 01100101 01110100 01111001") ; sleep(3)
        print("[   0.553012] Vs3r: N/t_Fo.-nd_Error ---[$ was-,here ~ ]---") ; sleep(4)
        print("")
        toolbar_width = 2000
        # setup toolbar
        sys.stdout.write("%s" % (" " * toolbar_width))
        sys.stdout.flush()
        sys.stdout.write("\b" * (toolbar_width+1)) # return to start of line, after '['
        # meccanismo
        for i in xrange(toolbar_width):
            time.sleep(0.003) # do real work here
            # update the bar
            sys.stdout.write("FatalError: Kernel Panic | ")
            sys.stdout.flush()
        # altro che non capisco
        sys.stdout.write("\n\n")
        time.sleep(1)
        return menu()
    #
    else:
        print("[ {}Errore{} ]: Scelta non valida. Usa {}help{} in caso di panico.".format(red,end, blue,end))
        return menu()

def help():
    print("                                                                                           ") ; sleep(.01)
    print(" {}Comandi:{}                                                                              ".format(bright_green + underline, end)) ; sleep(.01)
    print("    $ help / apt / banner / mapscii / net_restart / restart / kill / reboot / ftp / ping * ") ; sleep(.01)
    print("    $ info / repo update / updatedb / unbug / ifconfig [*] / os * / shutdown / quit/exit   ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Spoofing:{}                                                                             ".format(bright_green + underline, end)) ; sleep(.01)
    print("    $ toghost [ stop / start ] / macchanger                                                ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Cracking:{}                                                                             ".format(bright_green + underline, end)) ; sleep(.01)
    print("    $ androidpincrack * / extract-hash * / ioscrack *                                      ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Sniffing:{}                                                                             ".format(bright_green + underline, end)) ; sleep(.01)
    print("    $ bettercap / ettercap / morpheus / wireshark / mitmf / mitmap                         ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Scanning:{}                                                                             ".format(bright_green + underline, end)) ; sleep(.01)
    print("    [{}Local{}]:                                                                           ".format(bright_green, end)) ; sleep(.01)
    print("       $ nmap [ local / dlocal / web * / os * ] / netdiscover                              ") ; sleep(.01)
    print("    [{}Web{}]:                                                                             ".format(bright_green, end)) ; sleep(.01)
    print("        [{}Admin CP{}]:                                                                    ".format(bright_green, end)) ; sleep(.01)
    print("           $ cpscan *                                                                      ") ; sleep(.01)
    print("        [{}Scanners{} ({}Vulnerability + Others{})]:                                       ".format(bright_green, end, bright_green,end)) ; sleep(.01)
    print("           $ jaidam / uniscan * / droopescan / xsssniper * / vbscan * / dracnmap / zaproxy ") ; sleep(.01)
    print("           $ a2sv * / xattacker / sslscan * / wpscan * / xsstracer / arachni * / sshscan * ") ; sleep(.01)
    print("           $ dtect / striker / zenmap / crips / bingoo / whatweb * / siege * / onioff *    ") ; sleep(.01)
    print("           $ urlextractor * / instarecon * / dsxs * / joomscan *                           ") ; sleep(.01)
    print("        [{}Enumerators{}]:                                                                 ".format(bright_green, end)) ; sleep(.01)
    print("           $ sublist3r *                                                                   ") ; sleep(.01)
    print("        [{}All-in-one{}]:                                                                  ".format(bright_green, end)) ; sleep(.01)
    print("           $ sechub / tulpar / pentmenu                                                    ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Gathering:{}                                                                            ".format(bright_green + underline, end)) ; sleep(.01)
    print("    [{}Geolocalization{}]:                                                                 ".format(bright_green, end)) ; sleep(.01)
    print("       $ geoip * / whois *                                                                 ") ; sleep(.01)
    print("    [{}Web{}]:                                                                             ".format(bright_green, end)) ; sleep(.01)
    print("       $ sn1per * / red_hawk / maltego / inspy * / dmitry * / ktfconsole / osrframework    ") ; sleep(.01)
    print("       $ operativef / theharvester * / recon-ng                                            ") ; sleep(.01)
    print("    [{}Credentials Verification{}]:                                                        ".format(bright_green, end)) ; sleep(.01)
    print("       $ credmap * / knockmail                                                             ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Networking:{}                                                                           ".format(bright_green + underline, end)) ; sleep(.01)
    print("    [{}WiFi Attacks{}]:                                                                    ".format(bright_green, end)) ; sleep(.01)
    print("       $ airgeddon / fakeauth / fluxion / netattack / wifite / wpsbreaker / wifiphisher *  ") ; sleep(.01)
    print("       $ wifijammer /                                                                      ") ; sleep(.01)
    print("    [{}Exploitation{} ({}Local + Non-Local{})]:                                            ".format(bright_green,end, bright_green,end)) ; sleep(.01)
    print("       $ routersploit / wirespy / armitage / jexboss * / setoolkit / msfconsole / l0l      ") ; sleep(.01)
    print("       $ weeman  / shellsploit / eggshell / printerspam / koadic / pentestly / termineter  ") ; sleep(.01)
    print("       $ kayak / pybomber * / cisco-ge *                                                   ") ; sleep(.01)
    print("    [{}Web Exploitation{}]:                                                                ".format(bright_green, end)) ; sleep(.01)
    print("        [{}Dos e DDoS{}]:                                                                  ".format(bright_green, end)) ; sleep(.01)
    print("           $ zambie / xerxes * / ufonet / goldeneye * / torshammer *                       ") ; sleep(.01)
    print("        [{}BruteForce{}]:                                                                  ".format(bright_green, end)) ; sleep(.01)
    print("           $ blazy / hydra ftp * / xhydra / fbht / brutesploit / patator * / cheetah *     ") ; sleep(.01)
    print("        [{}SQLi{}]:                                                                        ".format(bright_green, end)) ; sleep(.01)
    print("           $ sqlmap [ scan * / inj ] / sqliv [ web / dork ] * / commix *                   ") ; sleep(.01)
    print("        [{}Site Cloner{}]:                                                                 ".format(bright_green, end)) ; sleep(.01)
    print("           $ httrack *                                                                     ") ; sleep(.01)
    print("        [{}Exploitation{}]:                                                                ".format(bright_green, end)) ; sleep(.01)
    print("           $ ipmipwn *                                                                     ") ; sleep(.01)
    print("    [{}Wan{}]:                                                                             ".format(bright_green,end)) ; sleep(.01)
    print("       $ ngrok [ tcp / http / tsl ] [port]                                                 ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}Exploiting:{}                                                                           ".format(bright_green + underline, end)) ; sleep(.01)
    print("    [{}Payload Generator{}]:                                                               ".format(bright_green, end)) ; sleep(.01)
    print("       $ chaos / brutal / arcanus / u3-pwn / overthruster / zirikatu / ezsploit / astroid  ") ; sleep(.01)
    print("       $ evildroid / kautilya / debinject / fatrat                                         ") ; sleep(.01)
    print("    [{}Keylogger Generator{}]:                                                             ".format(bright_green, end)) ; sleep(.01)
    print("       $ beelogger                                                                         ") ; sleep(.01)
    print("    [{}Spyware Generator{}]:                                                               ".format(bright_green, end)) ; sleep(.01)
    print("       $ saint                                                                             ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print(" {}All-in-one:{}                                                                           ".format(bright_green + underline, end)) ; sleep(.01)
    print("    $ hakkuf / trity / pythem / penbox / bluebox-ng / simple-ducky / discover / zarp       ") ; sleep(.01)
    print("    $ sb0x / atscan                                                                        ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    print("[ {}Attenzione{} ]: L'asterisco (*) indica la richiesta di un input. Digita il nome di un  ".format(bright_yellow,end)) ; sleep(.01)
    print("                Tool per ulteriori informazioni su di esso.                                ") ; sleep(.01)
    print("                                                                                           ") ; sleep(.01)
    return menu()
################################################################################
# tulpar menu
global tulpar_help
tulpar_help = """
 {}Comandi:{}
  show  [ options ]
  set   [ target  ]
  run   [ links  / e-mail  /  sql  /  xss  /  crawl  /  whois ]
  back
""".format(bright_green,end)
def tulpar_startup():
    print tulpar_help
    tulpar()
def tulpar_options():
    try:
        get_target = open("Logs/tulpar_target.txt").read()
    except IOError:
        get_target = "-"
    print("")
    print("---] Target  =  {}{}{}".format(blue,get_target,end))
    print("")
    tulpar()
def tulpar():
    class MyCompleter(object):  # Custom completer
        def __init__(self, options):
            self.options = sorted(options)
        def complete(self, text, state):
            if state == 0:  # on first trigger, build possible matches
                if text:  # cache matches (entries that start with entered text)
                    self.matches = [s for s in self.options
                                        if s and s.startswith(text)]
                else:  # no text entered, all matches possible
                    self.matches = self.options[:]
            # return match indexed by state
            try:
                return self.matches[state]
            except IndexError:
                return None
    completer = MyCompleter(["set","target","show","options","run","sql","xss",
    "links","e-mail","crawl","whois","back"])
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    while True:
        try:
            input = raw_input("[FS]-({}tulpar{}):".format(red,end))
        except KeyboardInterrupt:
            print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
            return tulpar()
        except EOFError:
            print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
            return tulpar()
        #
        tokens = input.split()
        try:
            command = tokens[0]
        except IndexError:
            command = None
        try:
            option = tokens[1]
        except IndexError:
            option = None
        try:
            argument = tokens[2]
        except IndexError:
            argument = None
        args = tokens[1:]
        if command == 'show':
            if option == 'options':
                return tulpar_options()
            else:
                print("[ {}Errore{} ]: {}Show{} richiede un argomento valido.".format(red,end, blue,end))
        elif command == 'run':
            try:
                get_target = open("Logs/tulpar_target.txt").read().splitlines()
            except IOError:
                print("[ {}Errore{} ]: opzioni mancanti per il parametro {}set{}.".format(red, end, blue, end))
                return tulpar()
            if option == 'links' or option == 'e-mail' or option == 'sql' or option == 'xss' or option == 'crawl' or option == 'whois':
                    os.system("cd Tools/tulpar/ && python tulpar.py {} {}".format(option,get_target[0]))
            else:
                print("[ {}Errore{} ]: argomenti mancanti per il parametro {}run{}.".format(red, end, blue, end))
        elif command == 'set':
            if option == 'target':
                if argument:
                    if 'https' in argument:
                        os.system("echo '{}' > Logs/tulpar_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return tulpar()
                    elif 'http' in argument:
                        os.system("echo '{}' > Logs/tulpar_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return tulpar()
                    elif 'http' not in argument:
                        os.system("echo 'http://{}' > Logs/tulpar_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return tulpar()
                else:
                    print("[ {}Errore{} ]: {}target{} richiede un bersaglio.".format(red, end, blue, end))
            else:
                print("[ {}Errore{} ]: {}set{} richiede un argomento valido.".format(red, end, blue, end))
        elif command == 'help':
            print tulpar_help
        elif command == 'back':
            try:
                os.remove("Logs/tulpar_target.txt")
            except OSError:
                pass
            return menu()
        elif command == 'clear' or command == 'reset':
            os.system(command)
        else:
            print("[ {}Errore{} ]: digita {}help{} in caso di panico".format(red, end, blue, end))
# droopescan menu
global droopescan_help
droopescan_help = """
 {}Comandi:{}
  show  [ options ]
  set   [ target  ]
  run   [ drupal  / joomla / moodle / silverstripe / wordpress ]
  back
""".format(bright_green,end)
def droopescan_startup():
    print droopescan_help
    droopescan()
def droopescan_options():
    try:
        get_target = open("Logs/droopescan_target.txt").read()
    except IOError:
        get_target = "-"
    print("")
    print("---] Target  = {}{}{}".format(blue,get_target,end))
    print("")
    droopescan()
def droopescan():
    class MyCompleter(object):  # Custom completer
        def __init__(self, options):
            self.options = sorted(options)
        def complete(self, text, state):
            if state == 0:  # on first trigger, build possible matches
                if text:  # cache matches (entries that start with entered text)
                    self.matches = [s for s in self.options
                                        if s and s.startswith(text)]
                else:  # no text entered, all matches possible
                    self.matches = self.options[:]
            # return match indexed by state
            try:
                return self.matches[state]
            except IndexError:
                return None
    completer = MyCompleter(["help","show","options","set","target","run","drupal","joomla","moodle","silverstripe","wordpress","back"])
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    while True:
        try:
            input = raw_input("[FS]-({}droopescan{}):".format(red,end))
        except KeyboardInterrupt:
            print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
            return droopescan()
        except EOFError:
            print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
            return droopescan()
        #
        tokens = input.split()
        try:
            command = tokens[0]
        except IndexError:
            command = None
        try:
            option = tokens[1]
        except IndexError:
            option = None
        try:
            argument = tokens[2]
        except IndexError:
            argument = None
        args = tokens[1:]
        if command == 'show':
            if option == 'options':
                return droopescan_options()
            else:
                print("[ {}Errore{} ]: {}Show{} richiede un argomento valido.".format(red, end, blue, end))
        elif command == 'run':
            try:
                get_target = open("Logs/droopescan_target.txt").read().splitlines()
            except IOError:
                print("[ {}Errore{} ]: opzioni mancanti per il parametro {}set{}.".format(red, end, blue, end))
                return droopescan()
            if option == 'drupal' or option == 'joomla' or option == 'moodle' or option == 'silverstripe' or option == 'wordpress':
                os.system("droopescan scan {} -u {}".format(option, get_target[0]))
            else:
                print("[ {}Errore{} ]: {}Run{} richiede un argomento valido.".format(red, end, blue, end))
        elif command == 'set':
            if option == 'target':
                if argument:
                    if 'https' in argument:
                        os.system("echo '{}' > Logs/droopescan_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return droopescan()
                    elif 'http' in argument:
                        os.system("echo '{}' > Logs/droopescan_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return droopescan()
                    elif 'http' not in argument:
                        os.system("echo 'http://{}' > Logs/droopescan_target.txt".format(argument))
                        print("---] Target = {}{}{} ".format(blue,argument,end))
                        return droopescan()
                else:
                    print("[ {}Errore{} ]: {}target{} richiede un bersaglio.".format(red, end, blue, end))
            else:
                print("[ {}Errore{} ]: {}target{} richiede un bersaglio.".format(red, end, blue, end))
        elif command == 'help':
            print droopescan_help
        elif command == 'back':
            try:
                os.remove("Logs/droopescan_target.txt")
            except OSError:
                pass
            return menu()
        elif command == 'clear' or command == 'reset':
            os.system(command)
        else:
            print("[ {}Errore{} ]: digita {}help{} in caso di panico".format(red, end, blue, end))
# sqlmap menu
global sqlmap_help
sqlmap_help = """
 {}Comandi:{}
  show  [ options ]
  set   [ target  / database / table / columns / thread [on/off] (default: off)]
  run
  back

[ {}Attenzione{} ]: {}columns{} richiede un input nel seguente modo:
                <column>,<column>,<column>...
""".format(bright_green,end, bright_yellow,end, blue,end)
def sqlmap_startup():
    print sqlmap_help
    sqlmap()
def sqlmap_options():
    try:
        get_target = open("Logs/sqlmap_target.txt").read().splitlines()
    except IOError:
        get_target = "-"
    try:
        get_database = open('Logs/sqlmap_database.txt').read().splitlines()
    except IOError:
        get_database = "-"
    try:
        get_table = open("Logs/sqlmap_table.txt").read().splitlines()
    except IOError:
        get_table = "-"
    try:
        get_columns = open("Logs/sqlmap_columns.txt").read().splitlines()
    except IOError:
        get_columns = "-"
    try:
        get_thread = open("Logs/sqlmap_thread.txt").read().splitlines()
    except IOError:
        get_thread = ["off"]
    print("")
    print(" [ {}Attenzione{} ]:".format(bright_yellow, end))
    print("  {}Database{}, {}Table{} e {}Columns{} vanno inseriti progressivamente con l'avanzare dell'attacco.".format(blue,end, blue,end, blue,end))
    print("  Usa {}run{} per ottenere i contenuti da impostare.".format(blue,end))
    print("")
    print("---] Target    =  {}{}{}".format(blue,get_target[0],end))
    print("---] Database  =  {}{}{}".format(blue,get_database[0],end))
    print("---] Table     =  {}{}{}".format(blue,get_table[0],end))
    print("---] Columns   =  {}{}{}".format(blue,get_columns[0],end))
    print("---] Thread    =  {}{}{}".format(blue,get_thread[0],end))
    print("")
    sqlmap()
def sqlmap():
    class MyCompleter(object):  # Custom completer
        def __init__(self, options):
            self.options = sorted(options)
        def complete(self, text, state):
            if state == 0:  # on first trigger, build possible matches
                if text:  # cache matches (entries that start with entered text)
                    self.matches = [s for s in self.options
                                        if s and s.startswith(text)]
                else:  # no text entered, all matches possible
                    self.matches = self.options[:]
            # return match indexed by state
            try:
                return self.matches[state]
            except IndexError:
                return None
    completer = MyCompleter(["help","show","options","set","target","database","table","columns","thread","on","off","run","back"])
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    try:
        command_input = raw_input("[FS]-({}sqlmap{}):".format(red,end))
    except KeyboardInterrupt:
        print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
        return sqlmap()
    except EOFError:
        print("\n[ {}Attenzione{} ]: Digita {}back{} per tornare al menu'.".format(bright_yellow,end, blue,end))
        return sqlmap()
    tokens = command_input.split()
    try:
        command = tokens[0]
    except IndexError:
        command = None
    try:
        option = tokens[1]
    except IndexError:
        option = None
    try:
        argument = tokens[2]
    except IndexError:
        argument = None
    try:
        argument2 = tokens[3]
    except IndexError:
        argument2 = None
    args = tokens[1:]
    if command == 'help':
        print sqlmap_help
        return sqlmap()
    elif command == 'clear' or command == 'reset':
        os.system(command)
        return sqlmap()
    elif command == 'show':
        if option == 'options':
            return sqlmap_options()
        else:
            print("[ {}Errore{} ]: {}Show{} richiede un opzione valida.".format(red,end, blue,end))
            return sqlmap()
    elif command == 'set':
        if option == 'target':
            if argument:
                if 'https' in argument:
                    os.system("echo '{}' > Logs/sqlmap_target.txt".format(argument))
                    print("---] Target = {}{}{} ".format(blue,argument,end))
                    return sqlmap()
                elif 'http' in argument:
                    os.system("echo '{}' > Logs/sqlmap_target.txt".format(argument))
                    print("---] Target = {}{}{} ".format(blue,argument,end))
                    return sqlmap()
                elif 'http' not in argument:
                    os.system("echo 'http://{}' > Logs/sqlmap_target.txt".format(argument))
                    print("---] Target = {}{}{} ".format(blue,argument,end))
                    return sqlmap()
            else: # else TARGET
                print("[ {}Errore{} ]: {}Target{} richiede un indirizzo.".format(red,end, blue,end))
                return sqlmap()
        elif option == 'database':
            if argument:
                if argument == '?' or argument == 'None' or argument == 'none' or argument == '-':
                    os.system("echo '-' > Logs/sqlmap_database.txt")
                    return sqlmap()
                os.system("echo '{}' > Logs/sqlmap_database.txt".format(argument))
                print("---] Database = {}{}{} ".format(blue,argument,end))
            else: # else DATABASE
                print("[ {}Errore{} ]: {}Database{} richiede un database.".format(red,end, blue,end))
            return sqlmap()
        elif option == 'table':
            if argument:
                if argument == '?' or argument == 'None' or argument == 'none' or argument == '-':
                    os.system("echo '-' > Logs/sqlmap_table.txt")
                    return sqlmap()
                os.system("echo '{}' > Logs/sqlmap_table.txt".format(argument))
                print("---] Table = {}{}{} ".format(blue,argument,end))
            else: # else TARGET
                print("[ {}Errore{} ]: {}Table{} richiede un table.".format(red,end, blue,end))
            return sqlmap()
        elif option == 'columns':
            if argument:
                if argument == '?' or argument == 'None' or argument == 'none' or argument == '-':
                    os.system("echo '-' > Logs/sqlmap_columns.txt")
                    return sqlmap()
                os.system("echo '{}' > Logs/sqlmap_columns.txt".format(argument))
                print("---] Columns = {}{}{} ".format(blue,argument,end))
            else: # else TARGET
                print("[ {}Errore{} ]: {}Columns{} richiede almeno una colonna.".format(red,end, blue,end))
            return sqlmap()
        elif option == 'thread':
            if argument == 'on' or argument == 'off':
                os.system("echo '{}' > Logs/sqlmap_thread.txt".format(argument))
                print("---] Thread = {}{}{} ".format(blue,argument,end))
            else:
                print("[ {}Errore{} ]: {}Thread{} va impostato {}on{} o {}off{}.".format(red,end, blue,end, blue,end, blue,end))
        else: # else SET
            print("[ {}Errore{} ]: {}Set{} richiede un argomento valido.".format(red,end, blue,end))
        return sqlmap()
    elif command == 'run':
        try:
            get_target = open("Logs/sqlmap_target.txt").read().splitlines()
        except IOError:
            print("[ {}Errore{} ]: Nessun indirizzo impostato.".format(red,end))
            return sqlmap()
        try:
            get_database = open('Logs/sqlmap_database.txt').read().splitlines()
        except IOError:
            get_database = "?"
        try:
            get_table = open("Logs/sqlmap_table.txt").read().splitlines()
        except IOError:
            get_table = "?"
        try:
            get_columns = open("Logs/sqlmap_columns.txt").read().splitlines()
        except IOError:
            get_columns = "?"
        try:
            get_thread = open("Logs/sqlmap_thread.txt").read().splitlines()
        except IOError:
            get_thread = "off"
        if get_thread == 'on':
            if get_target:
                if get_database != '?' or get_database != None:
                    if get_table != '?' or get_database != None:
                        if get_columns != '?' or get_database != None:
                            os.system("sqlmap -u {} -D {} -T {} -C {} --dump --thread 5".format(get_target[0],get_database[0],get_table[0],get_columns[0]))
                            return sqlmap()
                        os.system("sqlmap -u {} -D {} -T {} --columns --thread 5".format(get_target[0],get_database[0],get_table[0]))
                        return sqlmap()
                    os.system("sqlmap -u {} -D {} --tables --thread 5".format(get_target[0],get_database[0]))
                    return sqlmap()
                os.system("sqlmap -u {} --dbs --thread 5".format(get_target[0]))
                return sqlmap()
        if get_target:
            if get_database != '?' or get_database != None:
                if get_table != '?' or get_database != None:
                    if get_columns != '?' or get_database != None:
                        os.system("sqlmap -u {} -D {} -T {} -C {} --dump".format(get_target[0],get_database[0],get_table[0],get_columns[0]))
                        return sqlmap()
                    os.system("sqlmap -u {} -D {} -T {} --columns".format(get_target[0],get_database[0],get_table[0]))
                    return sqlmap()
                os.system("sqlmap -u {} -D {} --tables".format(get_target[0],get_database[0]))
                return sqlmap()
            os.system("sqlmap -u {} --dbs".format(get_target[0]))
            return sqlmap()
    elif command == 'back':
        try:
            os.remove("Logs/sqlmap_target.txt")
        except OSError:
            pass
        try:
            os.remove("Logs/sqlmap_database.txt")
        except OSError:
            pass
        try:
            os.remove("Logs/sqlmap_table.txt")
        except OSError:
            pass
        try:
            os.remove("Logs/sqlmap_columns.txt")
        except OSError:
            pass
        try:
            os.remove("Logs/sqlmap_thread.txt")
        except OSError:
            pass
        return menu()
    else:
        print("[ {}Errore{} ]: Comando non valido. You need '{}help{}'...".format(red,end, blue,end))
        return sqlmap()
################################################################################
def startup():
    os.system("rm Logs/verify_first_boot.txt")
    time.sleep(.5)
    print("[*] Avvio servizi, attendere...")
    time.sleep(1)
    print("")
    os.system("updatedb")
    print("[ {}OK{} ] Database aggiornato                     ".format(bright_green,end, dark_gray,end))
    os.system("service apache2 start")
    print("[ {}OK{} ] Servizio apache2 avviato                ".format(bright_green,end, dark_gray,end))
    os.system("service postgresql start")
    print("[ {}OK{} ] Servizio postgresql avviato             ".format(bright_green,end))
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[ {}OK{} ] Servizio ip_forward avviato             ".format(bright_green,end))
    print("")
    print("[ Welcome to {}fsociety{}! ]".format(red,end, red,end))
    print("")
    time.sleep(1)
    logo_print()
def logo_menu():
    sys.stdout.write(end)
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=28, cols=91))
    os.system("reset")
    now = datetime.datetime.now()
    print("")
    print('  88F888 88   88  dP""db 88  dP     .dP"Y8  dP"Yb   dP""b8 88 888888 888888 Yb  dP        ') ; sleep(.02)
    print('  88__   88   88 dP   `" 88odP      `Ybo." dP   Yb dP   `" 88 88__     88    YbdP         ') ; sleep(.02)
    print('  88""   Y8   8P Yb      88"Yb      o.`Y8b Yb   dP Yb      88 88""     88     8P          ') ; sleep(.02)
    print('  88     `YbudP   YboodP 88  Yb     8bodP   YbodP   YboodP 88 888888   88    dP  [{}v1.0.1{}]'.format(red,end)) ; sleep(.02)
    print(" [ {}Not_Found_Error{} / {}{}{} ]                                                         ".format(bright_green,end, bright_green,Tools,end)) ; sleep(.02)
    print("") ; sleep(.3)
    try:
        o = open("Logs/verify_first_boot.txt")
        return startup()
    except IOError:
        logo_print()
def logo_print():
    try:
        print("/ Public IP : {}".format(blue + requests.get('http://ip.42.pl/raw').text + end))
        print("/ Local IP  : {}".format(blue + socket.gethostbyname(socket.gethostname()) + end))
        print("/ Interface : {}".format(blue + netifaces.gateways()['default'][netifaces.AF_INET][1] + end))
    except (socket.error,requests.exceptions.ConnectionError,KeyError):
        if socket.error:
            print("---] Local IP   :  " + blue + "-" + end)
        if requests.exceptions.ConnectionError:
            print("---] Public IP  :  " + blue + "-  " + end + "[ {}Attenzione{} ]: Disattiva {}TorGhost{} o verifica la tua connessione.".format(bright_yellow,end, blue,end))
        if KeyError:
            print("---] Interface  :  " + blue + "-" + end)
    print("/ System    : {} {}".format(blue + platform.linux_distribution()[0], platform.system() + end))
    print("") ; sleep(.3)
    return menu()
################################################################################
def exit():
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=24, cols=80))
    os.system("clear")
    print("")
    sys.stdout.write("[*] Fermo i servizi ")
    sys.stdout.flush()
    os.system("service postgresql stop && echo 0 > /proc/sys/net/ipv4/ip_forward && service apache2 stop")
    sys.stdout.write("[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    print("")
    try:
        os.rename("*.txt", "Logs/")
    except OSError:
        pass
    sys.exit()
def info():
    print("") ; sleep(.02)
    print("[>] Autore: {}Not_Found_Error{}".format(blue, end)) ; sleep(.02)
    print("[ {}Attenzione{} ]:".format(bright_yellow,end)) ; sleep(.02)
    print("    Non mi assumo nessuna responsabilita' per l'uso che farai di questo") ; sleep(.02)
    print("    programma e per eventuali danni.") ; sleep(.02)
    print("    {}Pensa prima di premere invio!{}".format(red, end)) ; sleep(.02)
    print("") ; sleep(.02)
    print("[>] Compatibilita':") ; sleep(.02)
    print("    Kali Linux (32/64 bit)") ; sleep(.02)
    print("") ; sleep(.02)
    return menu()
################################################################################
if __name__ == '__main__':
    os.system("echo 'file destinato al macello' > Logs/verify_first_boot.txt") # verifica primo avvio
    print("""
[ {}Condizioni{} ]:
    Te che stai leggendo,
    rubare dati, invadere la Privacy di altre persone, e altro ancora legato
    all' "hacking" sono reati perseguibili penalmente.
    Con questo, non mi assumo nessuna responsabilita' per l'uso che ne farai
    di questo programma.
    {}Hai un cervello, dunque usalo prima di premere invio!{}
    """.format(underline + bright_green,end, red,end))
    print(" Accetti le condizioni?")
    try:
        startup_cond = raw_input(" [si/no]:")
        tokens = startup_cond.split()
        startup_cond = tokens[0]
    except IndexError:
        startup_cond = None
    except EOFError:
        sys.exit("\n")
    except KeyboardInterrupt:
        sys.exit("\n")
    if startup_cond == 's' or startup_cond == 'si' or startup_cond == None:
        logo_menu()
    else:
        sys.exit("")
