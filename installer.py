import os,sys,time,signal,readline,socket,requests
from time import sleep

global end, white, red, blue, green, dark_gray, bright_green, bright_cyan, bright_yellow, underline
end = '\033[0m'
white = '\033[1;37m'
red = '\033[1;31m'
blue = '\033[1;34m'
green = '\033[0;32m'
dark_gray = '\033[1;30m'
bright_green = '\033[1;32m'
bright_cyan = '\033[1;36m'
bright_yellow = '\033[1;33m'
black = "\033[1;30m"
#
underline = '\033[4m'

# Titolo finestra
sys.stdout.write("\x1b]2;Fuck Society Installer\x07")

euid = os.geteuid()
if euid != 0:
    print("[ {}Attenzione{} ]: Per proseguire sono necessari i permessi di root.".format(bright_yellow,end))
    time.sleep(.5)
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    # the next line replaces the currently-running process with the sudo
    os.execlpe('sudo', *args)

def main():
    print("")
    print("[ {}Attenzione{} ]:".format(bright_yellow,end))
    print("  Una volta eseguita l'installazione ti sconsiglio altamente di rinominare o ")
    print("  spostare la cartella di {}fsociety.py{}.".format(blue,end))
    print("  Se proprio devi, fallo prima.")
    print("  Non sono responsabile per l'uso che ne farai, sei dotato di un cervello")
    print("  dunque usalo!")
    print("")
    print("[>] Verranno installati tutti i Pacchetti e Tools. Continuare?".format(bright_yellow,end))
    main2()
def main2():
    try:
        command = raw_input("[si/no]:")
        tokens = command.split()
        command = tokens[0]
    except IndexError:
        command = None
    except EOFError:
        print("\n")
        print("[ {}Attenzione{} ]: Non potrai avviare {}fsociety.py{} senza l'installazione!\n".format(bright_yellow,end, blue,end))
        sys.exit()
    if command == 'si' or command == 's' or command == None:
        installer()
    elif command == 'no' or command == 'n':
        print("")
        sys.exit()
    else:
        print("[ {}Errore{} ]: Scelta non valida.".format(red,end))
        return main2()
def signal_handler(signal, frame):
    print("\n")
    print("[ {}Attenzione{} ]: Non potrai avviare {}fsociety.py{} senza l'installazione!\n".format(bright_yellow,end, blue,end))
    sys.exit()
signal.signal(signal.SIGINT, signal_handler)

def installer():
    print("")
    print("[*] Avvio...")
    time.sleep(2)
    os.system("reset")
    print("")
    print(" {}Processo Attuale{}                  {}Stato{}\n".format(underline,end, underline,end))
    sys.stdout.write(" Preliminari".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Updating' -e 'dpkg --add-architecture i386 && apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'") ; sleep(.1)
    os.system("xterm -T 'Updating' -e 'dpkg --configure -a && pip install --upgrade pip lxml && searchsploit -u'") ; sleep(.1)
    sys.stdout.write(23 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Rimuovo Vecchie Cartelle".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Setup' -e 'rm Logs/ -r && rm Tools/ -r && rm Oth/ -r'") ; sleep(.1)
    sys.stdout.write(10 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Creo Nuove Cartelle".format(bright_green,end))
    sys.stdout.flush()
    os.system("mkdir Logs && mkdir Tools && mkdir Oth")
    sys.stdout.write(15 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Installo Librerie e Pacchetti".format(bright_green,end))
    sys.stdout.flush()
    time.sleep(.1)
    os.system("xterm -T 'Installing Libraries...' -e 'pip install passlib flask wtforms pysocks pyopenssl netlib twisted pcapy dnspython urllib3 ipaddress pythem bs4 droopescan beautifulsoup4 sslyze requests netifaces capstone pefile colorama pylzma nmap jsonrpclib PyPDF2 olefile slowaes'") ; sleep(.1)
    os.system("xterm -T 'Installing Libraries...' -e 'python3 -m pip install mitmproxy'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'apt install siege whatweb termineter ipmitool recon-ng theharvester python-pip python3-pip dnsmasq wireshark u3-pwn osrframework jsql uniscan httrack arachni nmap python-nmap python-nfqueue wifiphisher gcc set golang upx-ucl wifite -y'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'apt install patator tor curl libxml2-utils commix sslscan libpcap-dev hostapd mitmf zaproxy hydra t50 lynx libssl-doc libssl-dev libdata-random-perl libfile-modified-perl libgd-perl libhook-lexwrap-perl -y'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'apt install joomscan libxslt1-dev screen sublist3r whois armitage zenmap libhtml-display-perl libhtml-tableextract-perl libhtml-tokeparser-simple-perl libterm-shell-perl libtext-autoformat-perl -y'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'apt install bc dnsutils libjpeg62-turbo-dev wondershaper libtext-reform-perl maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre zlib1g-dev libncurses5-dev lib32z1 lib32ncurses5 libwww-mechanize-formfiller-perl php-xml php-curl maltegoce python3 figlet bettercap -y'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'apt install libxml2-dev libffi-dev driftnet inspy goldeneye python-netifaces php-cgi lighttpd python-pycurl python-geoip python-whois python-crypto python-requests -y'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'easy_install wtforms scapy mechanize lxml html5lib validate_email pyDNS stem netifaces && sudo cpan JSON'") ; sleep(.1)
    os.system("xterm -T 'Installing Packages...' -e 'easy_install3 lxml'") ; sleep(.2)
    sys.stdout.write(5 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Scarico Tools".format(bright_green,end))
    sys.stdout.flush()
    # git clone
    time.sleep(1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Screetsec/TheFatRat.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/susmithHCK/torghost.git'")  ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/PowerScript/KatanaFramework.git'")  ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/reverse-shell/routersploit.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/v1s1t0r1sh3r3/airgeddon'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/AresS31/wirespy.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/shawarkhanethicalhacker/D-TECT.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/RedLectroid/OverThruster.git/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/4shadoww/hakkuframework.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/4w4k3/BeeLogger.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/tiagorlampert/CHAOS'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/neoneggplant/EggShell'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/zanyarjamal/xerxes.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/cys3c/secHub.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/graniet/operative-framework.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/scriptedp0ison/FakeAuth.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Screetsec/Dracnmap.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'wget https://raw.githubusercontent.com/exploitagency/github-kali-scripts/master/scripts/printerspam.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/1N3/Sn1per'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/zanyarjamal/zambie'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone --recursive https://github.com/FluxionNetwork/fluxion.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/epsylon/ufonet.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/r00t-3xp10it/morpheus.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/Tuhinshubhra/RED_HAWK.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/websploit/websploit.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/EgeBalci/ARCANUS.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Hadesy2k/sqliv'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://www.github.com/vasco2016/shellsploit-framework'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/M4sc3r4n0/Evil-Droid.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/rand0m1ze/ezsploit.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/pasahitz/zirikatu.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/susmithHCK/cpscan.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/SilentGhostX/HT-WPS-Breaker.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Hood3dRob1n/BinGoo.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/chrizator/netattack2'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/anilbaranyelken/tulpar.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/tiagorlampert/sAINT.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Moham3dRiahi/XAttacker.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/4w4k3/KnockMail.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/lightos/credmap.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/toxic-ig/Trity.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/UltimateHackers/Blazy.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Screetsec/Brutal.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/gbrindisi/xsssniper.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/M4sc3r4n0/astroid.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/UltimateHackers/Striker.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/joaomatosf/jexboss.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/samyoyo/weeman.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/PentesterES/AndroidPINCrack.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/x3omdax/PenBox.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/stasinopoulos/Jaidam.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/evict/SSHScan.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/GinjaChris/pentmenu.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/skysploit/simple-ducky.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/xdavidhu/mitmAP.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/hahwul/a2sv.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/zerosum0x0/koadic.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/AnarchyAngel/IPMIPWN.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/praetorian-inc/pentestly.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/samratashok/Kautilya.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/roissy/l0l.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/BRDumps/extract-hashes.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/leebaird/discover.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/hatRiot/zarp.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/1N3/XSSTracer.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/UndeadSec/Debinject.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/lostcitizen/sb0x-project.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Manisso/Crips.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/chinoogawa/fbht.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/ParrotSec/car-hacking-tools.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/rezasp/vbscan.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/cxdy/pybomber.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/foreni-packages/cisco-global-exploiter.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/DanMcInerney/wifijammer.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Karlheinzniebuhr/torshammer.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/AlisamTechnology/ATSCAN.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/eschultze/URLextractor.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/vergl4s/instarecon.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/Screetsec/BruteSploit.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/k4m4/onioff.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/thehappydinoa/iOSRestrictionBruteForce.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/sunnyelf/cheetah.git'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'git clone https://github.com/stamparm/DSXS.git'") ; sleep(.1)
    sys.stdout.write(21 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    # move
    sys.stdout.write(" Sposto Tools".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Setup' -e 'mv torshammer/ fbht/ Crips/ Debinject/ simple-ducky/ SSHScan/ AndroidPINCrack/ Evil-Droid/ TheFatRat/ torghost/ KatanaFramework/ routersploit/ airgeddon/ wirespy/ Tools/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'mv cheetah/ onioff/ URLextractor/ sb0x-project/ a2sv/ XSSTracer/ Kautilya/ 2sv/ Jaidam/ weeman/ jexboss/ D-TECT/ OverThruster/ BinGoo/ hakkuframework/ BeeLogger/ CHAOS/ EggShell/ xerxes/ Tools/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'mv DSXS/ ATSCAN/ car-hacking-tools/ l0l/ pentestly/ koadic/ pentmenu/ PenBox/ tulpar/ secHub/ operative-framework/ HT-WPS-Breaker/ FakeAuth/ Dracnmap/ Sn1per/ Tools/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'mv iOSRestrictionBruteForce/ instarecon/ wifijammer/ cisco-global-exploiter/ pybomber/ vbscan/ IPMIPWN/ mitmAP/ Striker/ cpscan/ zirikatu/ KnockMail/ netattack2/ zambie/ fluxion/ ufonet/ morpheus/ RED_HAWK/ websploit/ Tools/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'mv BruteSploit/ zarp/ discover/ extract-hashes/ astroid/ xsssniper/ Brutal/ Blazy/ Trity/ credmap/ XAttacker/ sAINT/  ARCANUS/ ezsploit/ sqliv/ shellsploit-framework/ Tools/'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'mv printerspam.sh Tools/'") ; sleep(.1)
    sys.stdout.write(22 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    # tools installer
        #manuali
    sys.stdout.write(" Installo Tools".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Setup' -e 'chmod +x Tools/TheFatRat/setup.sh && cd Tools/TheFatRat/ && ./setup.sh'") ; sleep(.1)
    #fatrat supply
    os.system("touch /usr/local/sbin/fatrat && echo '#!/bin/bash' > /usr/local/sbin/fatrat && echo 'cd {}/Tools/TheFatRat/ && ./fatrat' >> /usr/local/sbin/fatrat".format(os.getcwd())) ; sleep(.1)
    #
    os.system("xterm -T 'Setup' -e 'chmod +x Tools/torghost/install.sh && cd Tools/torghost/ && ./install.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/KatanaFramework/ && sh dependencies && python install'") ; sleep(.1)
        #automatici
    os.system("xterm -T 'Setup' -e 'unzip ngrok-*.zip && rm ngrok-*.zip && mv ngrok Tools/ && cp Tools/ngrok /usr/local/sbin/'")  ; sleep(.1) # ngrok
    os.system("xterm -T 'Setup' -e 'cd Tools/Trity && python install.py'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'chmod +x Tools/sAINT/configure.sh && cd Tools/sAINT/ && ./configure.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/routersploit/ && pip install -r requirements.txt'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e './Tools/hakkuframework/install'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/EggShell && easy_install pycrypto'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'gcc Tools/xerxes/xerxes.c -o Tools/xerxes/xerxes'") ; sleep(.3)
    os.system("xterm -T 'Setup' -e 'cd Tools/secHub/ && python installer.py && chmod +x /usr/bin/sechub'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'pip install -r Tools/operative-framework/requirements.txt'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'chmod +x Tools/zambie/Installer.sh && ./Tools/zambie/Installer.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/ufonet/ && python setup.py install && chmod +x ufonet'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/sqliv/ && pip install -r requirements.txt && python setup.py -i'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/shellsploit-framework/ && python setup.py -s install && cd ..'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'pip install -r Tools/tulpar/requirements'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/astroid/ && chmod +x astroid.sh setup.sh && ./setup.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/simple-ducky/ && ./install.sh'")
    os.system("xterm -T 'Setup' -e 'cd Tools/a2sv/ && ./install'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/pentestly/ && rm REQUIREMENTS && ./install.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/Kautilya && bundle install'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/l0l/ && make'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/zarp/ && pip install -r requirements.txt'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/Crips/ && chmod +x install.sh && ./install.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/fbht/ && python setup.py install'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/car-hacking-tools/ && make install'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/ATSCAN/ && chmod +x install.sh && ./install.sh'") ; sleep(.1)
    os.system("xterm -T 'Setup' -e 'cd Tools/instarecon/ && python setup.py install'") ; sleep(.1)
    # bluebox-ng
    os.system("xterm -T 'Setup' -e 'curl -sL https://raw.githubusercontent.com/jesusprubio/bluebox-ng/master/artifacts/installScripts/kali2.sh | sudo bash -'") ; sleep(.1)
    # only chmod
    os.system("chmod +x Tools/ezsploit/ezsploit.sh") ; sleep(.1)
    os.system("chmod +x Tools/airgeddon/airgeddon.sh") ; sleep(.1)
    os.system("chmod +x Tools/wirespy/wirespy.sh") ; sleep(.1)
    os.system("chmod +x Tools/D-TECT/d-tect.py") ; sleep(.1)
    os.system("chmod +x Tools/BeeLogger/bee.py") ; sleep(.1)
    os.system("chmod +x Tools/Dracnmap/dracnmap*.sh") ; sleep(.1)
    os.system("chmod +x Tools/printerspam.sh") ; sleep(.1)
    os.system("chmod +x Tools/Sn1per/sniper") ; sleep(.1)
    os.system("chmod +x Tools/websploit/websploit") ; sleep(.1)
    os.system("chmod +x Tools/ARCANUS/ARCANUS") ; sleep(.1)
    os.system("chmod +x Tools/Evil-Droid/evil-droid") ; sleep(.1)
    os.system("chmod +x Tools/zirikatu/zirikatu.sh") ; sleep(.1)
    os.system("chmod +x Tools/Brutal/Brutal.sh") ; sleep(.1)
    os.system("chmod +x Tools/BruteSploit/Brutesploit") ; sleep(.1)
    sys.stdout.write(20 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    # fase finale
    sys.stdout.write(" Installo per Utilita'".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Setup' -e 'apt install playonlinux ftp python3-setuptools python3-dev netdiscover dsniff yum -y && easy_install3 pip && pip install wafw00f request pythonwhois && pip3 install pyasn1 tabulate impacket six termcolor colorama'") ; sleep(.01)
    sys.stdout.write(13 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Pulisco".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Wiping...' -e 'dpkg --configure -a'") ; sleep(.1)
    os.system("xterm -T 'Wiping...' -e 'mv psexecspray.py pycrypto-2.6.win32-py2.7.exe python-2.7.10.msi pywin32.exe vcredist_x86.exe Oth/'") ; sleep(.1)
    os.system("xterm -T 'Wiping...' -e 'mv impacket/ PLATLIB/ SCRIPTS/ ../server.crt ../server.key PyInstaller*.zip Oth/'") ; sleep(.1)
    sys.stdout.write(27 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Aggiornamento di Sicurezza".format(bright_green,end))
    sys.stdout.flush()
    os.system("xterm -T 'Updating...' -e 'apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && dpkg --configure -a'") ; sleep(.1)
    # Verifica installazione fsociety
    os.system("echo 'NON CANCELLARE QUESTO FILE' > Tools/Complete.txt")
    #
    os.system("touch /usr/local/sbin/fsociety && chmod +x /usr/local/sbin/fsociety && echo '#!/bin/bash' > /usr/local/sbin/fsociety && echo 'cd {}/ && python fsociety.py' >> /usr/local/sbin/fsociety".format(os.getcwd()))
    #
    sys.stdout.write(8 * " " + "[ {}DONE{} ]\n".format(bright_green,end))
    sys.stdout.flush()
    print("")
    print("[ {}DONE{} ]: Installazione Completata.".format(bright_green,end))
    print("          Avvia fsociety con {}fsociety{} ovunque nella shell oppure dalla sua".format(blue,end))
    print("          cartella con {}python fsociety.py{}.".format(blue,end))
    print("")
    sys.exit()

#
def connection_detector():
    print("[{}Fuck Society Installer{}]\n".format(bright_green, end)) ; sleep(.2)
    sys.stdout.write("[*] Verifico Connessione Internet ")
    sys.stdout.flush()
    try:
        requests.get('http://ip.42.pl/raw')
        sys.stdout.write("[{} OK {}]\n".format(bright_green, end))
        sys.stdout.flush()
        time.sleep(.5)
        return main()
    except requests.exceptions.ConnectionError:
        sys.stdout.write(" [{} Fail {}]\n".format(red, end))
        sys.stdout.flush()
        print("")
        print("[ {}Attenzione{} ]: Disattiva {}TorGhost{} o verifica la tua connessione.\n".format(bright_yellow,end, blue,end))
        sys.exit()
connection_detector()
#
signal.pause()
