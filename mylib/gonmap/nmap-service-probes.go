package gonmap

var nmapServiceProbes = `
# Nmap service detection probe list -*- mode: fundamental; -*-
# $Id$
#
# This is a database of custom probes and expected responses that the
# Nmap Security Scanner ( https://nmap.org ) uses to
# identify what services (eg http, smtp, dns, etc.) are listening on
# open ports.  Contributions to this database are welcome.
# Instructions for obtaining and submitting service detection fingerprints can
# be found in the Nmap Network Scanning book and online at
# https://nmap.org/book/vscan-community.html
#
# This collection of probe data is (C) 1998-2020 by Insecure.Com
# LLC.  It is distributed under the Nmap Public Source license as
# provided in the LICENSE file of the source distribution or at
# https://nmap.org/data/LICENSE .  Note that this license
# requires you to license your own work under a compatible open source
# license.  If you wish to embed Nmap technology into proprietary
# software, we sell alternative licenses (contact sales@insecure.com).
# Dozens of software vendors already license Nmap technology such as
# host discovery, port scanning, OS detection, and version detection.
# For more details, see https://nmap.org/book/man-legal.html
#
# For details on how Nmap version detection works, why it was added,
# the grammar of this file, and how to detect and contribute new
# services, see https://nmap.org/book/vscan.html.

# The Exclude directive takes a comma separated list of ports.
# The format is exactly the same as the -p switch.
# Exclude T:9100-9107

# This is the NULL probe that just compares any banners given to us
##############################NEXT PROBE##############################
Probe TCP NULL q||
rarity 2
# Wait for at least 6 seconds for data.  It used to be 5, but some
# smtp services have lately been instituting an artificial pause (see
# FEATURE('greet_pause') in Sendmail, for example)
totalwaitms 6000
# If the service closes the connection before 3 seconds, it's probably
# tcpwrapped. Adjust up or down depending on your false-positive rate.
tcpwrappedms 3000

softmatch smtp m|^220[\s-].*smtp[^\r]*\r\n|i
softmatch ftp m=^220[\s-].*(ftp|FileZilla)[^\r]*\r\n=i
match ftp m|^220 .*\r\n| p/FTP/ 
match ftp m|^220[- ]+.*\r\n| p/FTP/ 
match ftp m|^220.*\r\n| p/FTP/

match ssh m|^SSH-[0-9\.]+-.*\r\n| p/SSH/

match mysql m|^[0-9a-f]{4}[^0-9a-f]*[5-8]\.[0-9]+\..*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*MySQL.*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*MariaDB.*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*server version.*| p/MySQL/
match mysql m|^[0-9a-f]{4}| p/MySQL/

match mysql m|^.\0\0\0\n(.\\.[-_~.+\\w]+)\0| p/MySQL/
match mysql m|^.\0\0\0ÿj\x04'[\\d.]+' .* MySQL| p/MySQL/
match mysql m|^\x48\0\0\0.*allowed.*| p/MySQL/

match telnet m|^\xFF| p/Telnet/
match svnserve m|^\( success \( \d \d \( (?:ANONYMOUS )?\) \( | p/Subversion/ cpe:/a:apache:subversion/


######################## own add end

match apachemq m|^\0\0..\x01ActiveMQ\0\0\0.\x01\0\0.*\x0cProviderName\t\0\x08ActiveMQ.*\x0fPlatformDetails\t..JVM: (\d[^,]*), [^,]*, Oracle Corporation, OS: Linux, (\d\.[\d.]+)[^,]*, ([\w_-]+).*\x0fProviderVersion\t..(\d[\w._-]*)|s p/ActiveMQ OpenWire transport/ v/$4/ i/Java $1; arch: $3/ o/Linux $2/ cpe:/a:apache:activemq:$4/ cpe:/o:linux:linux_kernel:$2/a
softmatch apachemq m|^\0\0..\x01ActiveMQ\0| p/ActiveMQ OpenWire transport/
match docker-swarm m|^\0\0\0\x04\0\0\0\0\0\0\0\x04\x08\0\0\0\0\0\0\x0e\xff\xf1| p/Docker Swarm/ cpe:/a:redhat:docker/



# DAZ Studio 4.5, port 27997
match valentinadb m|^dddd\0\0\0\0\0\0\0\x0b| p/Valentina DB/

match varnish-cli m|^200 \d+ +\n-----------------------------\nVarnish HTTP accelerator CLI.\n-----------------------------\nType 'help' for command list\.\nType 'quit' to close CLI session\.\n| p/Varnish Cache CLI/ v/2.1.0 - 2.1.3/ i/open/ cpe:/a:varnish-cache:varnish:2.1/
# vident field is uname -s,uname -r,uname -m
match varnish-cli m|^200 \d+ +\n-----------------------------\nVarnish HTTP accelerator CLI.\n-----------------------------\n([^,]+),([^,]+),[^\n]*\n\nType 'help' for command list\.\nType 'quit' to close CLI session\.\n| p/Varnish Cache CLI/ v/2.1.4/ o/$1 $2/ cpe:/a:varnish-cache:varnish:2.1.4/
match varnish-cli m|^200 \d+ +\n-----------------------------\nVarnish Cache CLI 1.0\n-----------------------------\n([^,]+),([^,]+),[^\n]*\n\nType 'help' for command list\.\nType 'quit' to close CLI session\.\n\n| p/Varnish Cache CLI/ v/2.1.5 - 3.0.3/ o/$1 $2/ cpe:/a:varnish-cache:varnish/
match varnish-cli m|^200 \d+ +\n-----------------------------\nVarnish Cache CLI 1.0\n-----------------------------\n([^,]+),([^,]+),[^\n]*\nvarnish-([\w._-]+) revision [0-9a-f]+\n\nType 'help' for command list\.\nType 'quit' to close CLI session\.\n\n| p/Varnish Cache CLI/ v/$3/ o/$1 $2/ cpe:/a:varnish-cache:varnish:$3/
match varnish-cli m|^107 59      \n[a-z]{32}\n\nAuthentication required\.\n\n| p/Varnish Cache CLI/ i/authentication required/ cpe:/a:varnish-cache:varnish/

# TODO kerio?
#match ftp m|^421 Service not available \(The FTP server is not responding\.\)\n$| v/unknown FTP server//service not responding/
match vdr m|^220 (\S+) SVDRP VideoDiskRecorder (\d[^\;]+);| p/VDR/ v/$2/ d/media device/ h/$1/
match vdr m|^Access denied!\n$| p/VDR/ d/media device/

softmatch ftp m|^220 Welcome to ([-.\w]+) FTP.*\r\n$|i h/$1/
softmatch ftp m|^220 ([-.\w]+) [-.\w ]+ftp.*\r\n$|i h/$1/
softmatch ftp m|^220-([-.\w]+) [-.\w ]+ftp.*\r\n220|i h/$1/
softmatch ftp m|^220 [-.\w ]+ftp.*\r\n$|i
softmatch ftp m|^220-[-.\w ]+ftp.*\r\n220|i
softmatch ftp m|^220[- ].*ftp server.*\r\n|i
softmatch ftp m|^220-\r?\n220 - ftp|i

match imap m|^\* OK.*| p/IMAP/


match ipcam m|^\0\0\0\x10\0\0\0\x1e\0\0\0\x1e\0\0\0\0| p/Hikvision IPCam control port/
match ipcam m|^8\0\0\0l\0{19}....\0\0\0\0\xc4\x87#@\0\0\0\0\xf5\x8f\x05Tmrmt_hello\0{26}\x0e\0\0\0\xe8\x87#@\0\0\0\x00(\w+)\n\0| p/LeFun or MAISI IP camera/ i/ID: $1/ d/webcam/

match mysql m|^.\0\0\0\xff..Host .* is not allowed to connect to this MySQL server$|s p/MySQL/ i/unauthorized/ cpe:/a:mysql:mysql/
match mysql m|^.\0\0\0\xff..Host .* is not allowed to connect to this MariaDB server$|s p/MariaDB/ i/unauthorized/ cpe:/a:mariadb:mariadb/
match mysql m|^.\0\0\0\xff..Too many connections|s p/MySQL/ i/Too many connections/ cpe:/a:mysql:mysql/
match mysql m|^.\0\0\0\xff..Host .* is blocked because of many connection errors|s p/MySQL/ i/blocked - too many connection errors/ cpe:/a:mysql:mysql/
match mysql m|^.\0\0\0\xff..Le h\xf4te '[-.\w]+' n'est pas authoris\xe9 \xe0 se connecter \xe0 ce serveur MySQL$| p/MySQL/ i/unauthorized; French/ cpe:/a:mysql:mysql::::fr/
match mysql m|^.\0\0\0\xff..Host hat keine Berechtigung, eine Verbindung zu diesem MySQL Server herzustellen\.|s p/MySQL/ i/unauthorized; German/ cpe:/a:mysql:mysql::::de/
match mysql m|^.\0\0\0\xff..Host '[-\w_.]+' hat keine Berechtigung, sich mit diesem MySQL-Server zu verbinden|s p/MySQL/ i/unauthorized; German/ cpe:/a:mysql:mysql::::de/
match mysql m|^.\0\0\0\xff..Al sistema '[-.\w]+' non e${backquote} consentita la connessione a questo server MySQL$|s p/MySQL/ i/unauthorized; Italian/ cpe:/a:mysql:mysql::::it/

match mysql m|^.\0\0\0...Servidor '[-.\w]+' est\xe1 bloqueado por muchos errores de conexi\xf3n\.  Desbloquear con 'mysqladmin flush-hosts'|s p/MySQL/ i/blocked - too many connection errors; Spanish/ cpe:/a:mysql:mysql::::es/
match mysql m|^.\0\0\0...'Host' '[-.\w]+' n\xe3o tem permiss\xe3o para se conectar com este servidor MySQL| p/MySQL/ i/unauthorized; Spanish/ cpe:/a:mysql:mysql::::es/
match mysql m|^.\0\0\0\x0a([\w._-]+)\0............\0\x5f\xd3\x2d\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0............\0$|s p/Drizzle/ v/$1/
match mysql m|^.\0\0\0\x0a([\w._-]+)\0............\0\x5f\xd1\x2d\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0............\0$|s p/Drizzle/ v/$1/

#MariaDB
match mysql m|^.\0\0\0\x0a(5\.[-_~.+:\w]+MariaDB-[-_~.+:\w]+~bionic)\0|s p/MySQL/ v/$1/ cpe:/a:mariadb:mariadb:$1/ o/Linux/ cpe:/o:canonical:ubuntu_linux:18.04/
match mysql m|^.\0\0\0\x0a(5\.[-_~.+:\w]+MariaDB-[-_~.+:\w]+)\0|s p/MySQL/ v/$1/ cpe:/a:mariadb:mariadb:$1/


match mysql m|^.\0\0\0.(3\.[-_~.+\w]+)\0.*\x08\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0$|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\x0a(3\.[-_~.+\w]+)\0...\0|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\x0a(4\.[-_~.+\w]+)\0|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\x0a(5\.[-_~.+\w]+)\0|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\x0a(6\.[-_~.+\w]+)\0...\0|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\x0a(8\.[-_~.+\w]+)\0...\0|s p/MySQL/ v/$1/ cpe:/a:mysql:mysql:$1/
match mysql m|^.\0\0\0\xffj\x04'[\d.]+' .* MySQL|s p/MySQL/ cpe:/a:mysql:mysql/

# This will get awkward if Sphinx goes to version 3.
match mysql m|^.\0\0\0.([012]\.[\w.-]+)(?: \([0-9a-f]+\))?\0|s p/Sphinx Search SphinxQL/ v/$1/ cpe:/a:sphinx:sphinx_search:$1/

match mysql m|^.\0\0\0\x0a(0[\w._-]+)\0| p/MySQL instance manager/ v/$1/ cpe:/a:mysql:mysql:$1/

match minisql m|^.\0\0\x000:23:([\d.]+)\n$|s p/Mini SQL/ v/$1/

# xrdp disconnects this way if you look at it funny.
match ms-wbt-server m|^\x03\0\0\t\x02\xf0\x80!\x80| p/xrdp/ cpe:/a:jay_sorg:xrdp/
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a

match pop3 m|^\+OK.*| p/POP3/



# RFC 1939 suggests <process-ID.clock@hostname> for the timestamp
softmatch pop3 m|^\+OK [^<]+ <[\d.]+@([\w.-]+)>\r\n$| h/$1/
# otherwise, just softmatch anything
softmatch pop3 m|^\+OK [-\[\]\(\)!,/+:<>@.\w ]+\r\n$|

match pptp m|^\0\x10\0\x01\x1a\+<M\0\x05\0\0\0\0\0\x01$| p/Point to Point Tunneling Protocol/

match smtp m|^220.*$| p/SMTP/
match smtp m|^421.*$| p/SMTP/
match smtp m|^554.*$| p/SMTP/

# F-Secure/WRQ
match ssh m|^SSH-([\d.]+)-([\d.]+) F-Secure SSH Windows NT Server\r?\n| p/F-Secure WinNT sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\d.]+) dss F-SECURE SSH\r?\n| p/F-Secure sshd/ v/$2/ i/dss-only; protocol $1/
match ssh m|^SSH-([\d.]+)-([\d.]+) F-SECURE SSH.*\r?\n| p/F-Secure sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-ReflectionForSecureIT_([-\w_.]+) - Process Software MultiNet\r\n| p/WRQ Reflection for Secure IT sshd/ v/$2/ i/OpenVMS MultiNet; protocol $1/ o/OpenVMS/ cpe:/o:hp:openvms/a
match ssh m|^SSH-([\d.]+)-ReflectionForSecureIT_([-\w_.]+)\r?\n| p/WRQ Reflection for Secure IT sshd/ v/$2/ i/protocol $1/

# SCS
match ssh m|^SSH-(\d[\d.]+)-SSH Protocol Compatible Server SCS (\d[-.\w]+)\r?\n| p/SCS NetScreen sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-SSH Compatible Server\r?\n| p/SCS NetScreen sshd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-([\d.]+) SSH Secure Shell Tru64 UNIX\r?\n| p/SCS sshd/ v/$2/ i/protocol $1/ o/Tru64 UNIX/ cpe:/o:compaq:tru64/a
match ssh m|^SSH-([\d.]+)-(\d+\.\d+\.\d+) SSH Secure Shell| p/SCS sshd/ v/$2/ i/protocol $1/
match ssh m|^sshd: SSH Secure Shell (\d[-.\w]+) on ([-.\w]+)\nSSH-(\d[\d.]+)-| p/SCS SSH Secure Shell/ v/$1/ i/on $2; protocol $3/
match ssh m|^sshd: SSH Secure Shell (\d[-.\w]+) \(([^\r\n\)]+)\) on ([-.\w]+)\nSSH-(\d[\d.]+)-| p/SCS sshd/ v/$1/ i/$2; on $3; protocol $4/
match ssh m|^sshd2\[\d+\]: .*\r\nSSH-([\d.]+)-(\d[-.\w]+) SSH Secure Shell \(([^\r\n\)]+)\)\r?\n| p/SCS sshd/ v/$2/ i/protocol $1; $3/
match ssh m|^SSH-([\d.]+)-(\d+\.\d+\.[-.\w]+)| p/SCS sshd/ v/$2/ i/protocol $1/

# OpenSSH
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) Debian-(\S*maemo\S*)\r?\n| p/OpenSSH/ v/$2 Debian $3/ i/Nokia Maemo tablet; protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:debian:debian_linux/ cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Debian[ -_](.*ubuntu.*)\r\n| p/OpenSSH/ v/$2 Debian $3/ i/Ubuntu Linux; protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:canonical:ubuntu_linux/ cpe:/o:linux:linux_kernel/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Ubuntu[ -_]([^\r\n]+)\r?\n| p/OpenSSH/ v/$2 Ubuntu $3/ i/Ubuntu Linux; protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:canonical:ubuntu_linux/ cpe:/o:linux:linux_kernel/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Debian[ -_]([^\r\n]+)\r?\n| p/OpenSSH/ v/$2 Debian $3/ i/protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:debian:debian_linux/ cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-([\d.]+)-OpenSSH_[\w.]+-FC-([\w.-]+)\.fc(\d+)\r\n| p/OpenSSH/ v/$2 Fedora/ i/Fedora Core $3; protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:fedoraproject:fedora_core:$3/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD-([\d]+)\r?\n| p/OpenSSH/ v/$2/ i/FreeBSD $3; protocol $1/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD localisations (\d+)\r?\n| p/OpenSSH/ v/$2/ i/FreeBSD $3; protocol $1/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m=^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD-openssh-portable-(?:base-|amd64-)?[\w.,]+\r?\n= p/OpenSSH/ v/$2/ i/protocol $1/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD-openssh-portable-overwrite-base| p/OpenSSH/ v/$2/ i/protocol $1; overwrite base SSH/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD-openssh-gssapi-| p/OpenSSH/ v/$2/ i/gssapi; protocol $1/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) FreeBSD\n| p/OpenSSH/ v/$2/ i/protocol $1/ o/FreeBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:freebsd:freebsd/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) miniBSD-([\d]+)\r?\n| p/OpenSSH/ v/$2/ i/MiniBSD $3; protocol $1/ o/MiniBSD/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) NetBSD_Secure_Shell-([\w._+-]+)\r?\n| p/OpenSSH/ v/$2/ i/NetBSD $3; protocol $1/ o/NetBSD/ cpe:/a:openbsd:openssh:$2/ cpe:/o:netbsd:netbsd/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)_Mikrotik_v([\d.]+)\r?\n| p/OpenSSH/ v/$2 mikrotik $3/ i/protocol $1/ d/router/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) in RemotelyAnywhere ([\d.]+)\r?\n| p/OpenSSH/ v/$2/ i/RemotelyAnywhere $3; protocol $1/ o/Windows/ cpe:/a:openbsd:openssh:$2/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)\+CAN-2004-0175\r?\n| p/OpenSSH/ v/$2+CAN-2004-0175/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) NCSA_GSSAPI_20040818 KRB5\r?\n| p/OpenSSH/ v/$2 NCSA_GSSAPI_20040818 KRB5/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
# http://www.psc.edu/index.php/hpn-ssh
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)[-_]hpn(\w+) *(?:\"\")?\r?\n| p/OpenSSH/ v/$2/ i/protocol $1; HPN-SSH patch $3/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+\+sftpfilecontrol-v[\d.]+-hpn\w+)\r?\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+-hpn) NCSA_GSSAPI_\d+ KRB5\r?\n| p/OpenSSH/ v/$2/ i/protocol $1; kerberos support/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_3\.4\+p1\+gssapi\+OpenSSH_3\.7\.1buf_fix\+2006100301\r?\n| p/OpenSSH/ v/3.4p1 with CMU Andrew patches/ i/protocol $1/ cpe:/a:openbsd:openssh:3.4p1/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+\.RL)\r?\n| p/OpenSSH/ v/$2 Allied Telesis/ i/protocol $1/ d/switch/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+-CERN\d+)\r?\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+\.cern-hpn)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+-hpn)\r?\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+-pwexp\d+)\r?\n| p/OpenSSH/ v/$2/ i/protocol $1/ o/AIX/ cpe:/a:openbsd:openssh:$2/ cpe:/o:ibm:aix/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)-chrootssh\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-Nortel\r?\n| p/Nortel SSH/ i/protocol $1/ d/switch/ cpe:/a:openbsd:openssh/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.]+)[-_]hpn(\w+) DragonFly-| p/OpenSSH/ v/$2/ i/protocol $1; HPN-SSH patch $3/ o/DragonFlyBSD/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.]+) DragonFly-| p/OpenSSH/ v/$2/ i/protocol $1/ o/DragonFlyBSD/ cpe:/a:openbsd:openssh:$2/
# Not sure about the next 2 being these specific devices:
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w_.-]+) FIPS\n| p/OpenSSH/ v/$2/ i/protocol $1; Imperva SecureSphere firewall/ d/firewall/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w_.-]+) FIPS\r\n| p/OpenSSH/ v/$2/ i/protocol $1; Cisco NX-OS/ d/switch/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w_.-]+) NCSA_GSSAPI_GPT_([-\w_.]+) GSI\n| p/OpenSSH/ v/$2/ i/protocol $1; NCSA GSSAPI authentication patch $3/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) \.\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) PKIX\r\n| p/OpenSSH/ v/$2/ i/protocol $1; X.509 v3 certificate support/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)-FIPS\(capable\)\r\n| p/OpenSSH/ v/$2/ i/protocol $1; FIPS capable/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)-sshjail\n| p/OpenSSH/ v/$2/ i/protocol $1; sshjail patch/ cpe:/a:openbsd:openssh:$2/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) Raspbian-([^\r\n]+)\r?\n| p/OpenSSH/ v/$2 Raspbian $3/ i/protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) OVH-rescue\r\n| p/OpenSSH/ v/$2/ i/protocol $1; OVH hosting rescue/ cpe:/a:openbsd:openssh:$2/a
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) Trisquel_GNU/linux_([\d.]+)(?:-\d+)?\r\n| p/OpenSSH/ v/$2/ i/protocol $1; Trisquel $3/ o/Linux/ cpe:/a:openbsd:openssh:$2/a cpe:/o:linux:linux_kernel/a cpe:/o:trisquel_project:trisquel_gnu%2flinux:$3/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) \+ILOM\.2015-5600\r\n| p/OpenSSH/ v/$2/ i/protocol $1; ILOM patched CVE-2015-5600/ cpe:/a:openbsd:openssh:$2/a cpe:/h:oracle:integrated_lights-out/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+) SolidFire Element \r\n| p/OpenSSH/ v/$2/ i/protocol $1; NetApp SolidFire storage node/ cpe:/a:openbsd:openssh:$2/a cpe:/o:netapp:element_software/

# Choose your destiny:
# 1) Match all OpenSSHs:
#match ssh m/^SSH-([\d.]+)-OpenSSH[_-]([\S ]+)/i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
# 2) Don't match unknown SSHs (and generate fingerprints)
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)\s*\r?\n|i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/

# These are strange ones. These routers pretend to be OpenSSH, but don't do it that well (see the \r):
match ssh m|^SSH-2\.0-OpenSSH\r?\n| p/Linksys WRT45G modified dropbear sshd/ i/protocol 2.0/ d/router/
match ssh m|^SSH-2\.0-OpenSSH_3\.6p1\r?\n| p|D-Link/Netgear DSL router modified dropbear sshd| i/protocol 2.0/ d/router/

match ssh m|^\0\0\0\$\0\0\0\0\x01\0\0\0\x1bNo host key is configured!\n\r!\"v| p/Foundry Networks switch sshd/ i/broken: No host key configured/
match ssh m|^SSH-(\d[\d.]+)-SSF-(\d[-.\w]+)\r?\n| p/SSF French SSH/ v/$2/ i/protocol $1/
match ssh m|^SSH-(\d[\d.]+)-lshd_(\d[-.\w]+) lsh - a free ssh\r\n\0\0| p/lshd secure shell/ v/$2/ i/protocol $1/
match ssh m|^SSH-(\d[\d.]+)-lshd-(\d[-.\w]+) lsh - a GNU ssh\r\n\0\0| p/lshd secure shell/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Sun_SSH_(\S+)| p/SunSSH/ v/$2/ i/protocol $1/ cpe:/a:sun:sunssh:$2/
match ssh m|^SSH-([\d.]+)-meow roototkt by rebel| p/meow SSH ROOTKIT/ i/protocol $1/
# Akamai hosted systems tend to run this - found on www.microsoft.com
match ssh m|^SSH-(\d[\d.]*)-(AKAMAI-I*)\r?\n$| p/Akamai SSH/ v/$2/ i/protocol $1/ cpe:/a:akamai:ssh:$2/
match ssh m|^SSH-(\d[\d.]*)-AKAMAI-([\d.]+)\r?\n$| p/Akamai SSH/ v/$2/ i/protocol $1/ cpe:/a:akamai:ssh:$2/
match ssh m|^SSH-(\d[\d.]*)-(Server-V)\r?\n$| p/Akamai SSH/ v/$2/ i/protocol $1/ cpe:/a:akamai:ssh:$2/
match ssh m|^SSH-(\d[\d.]*)-(Server-VI)\r?\n$| p/Akamai SSH/ v/$2/ i/protocol $1/ cpe:/a:akamai:ssh:$2/
match ssh m|^SSH-(\d[\d.]*)-(Server-VII)\r?\n| p/Akamai SSH/ v/$2/ i/protocol $1/ cpe:/a:akamai:ssh:$2/
match ssh m|^SSH-(\d[\d.]+)-Cisco-(\d[\d.]+)\r?\n$| p/Cisco SSH/ v/$2/ i/protocol $1/ o/IOS/ cpe:/a:cisco:ssh:$2/ cpe:/o:cisco:ios/a
match ssh m|^SSH-(\d[\d.]+)-CiscoIOS_([\d.]+)XA\r?\n| p/Cisco SSH/ v/$2/ i/protocol $1; IOS XA/ o/IOS/ cpe:/a:cisco:ssh:$2/ cpe:/o:cisco:ios/a
match ssh m|^\r\nDestination server does not have Ssh activated\.\r\nContact Cisco Systems, Inc to purchase a\r\nlicense key to activate Ssh\.\r\n| p/Cisco CSS SSH/ i/Unlicensed/ cpe:/a:cisco:ssh/
match ssh m|^SSH-(\d[\d.]+)-VShell_(\d[_\d.]+) VShell\r?\n$| p/VanDyke VShell sshd/ v/$SUBST(2,"_",".")/ i/protocol $1/ cpe:/a:vandyke:vshell:$SUBST(2,"_",".")/
match ssh m|^SSH-2\.0-0\.0 \r?\n| p/VanDyke VShell sshd/ i/version info hidden; protocol 2.0/ cpe:/a:vandyke:vshell/
match ssh m|^SSH-([\d.]+)-([\w.]+) VShell\r?\n| p/VanDyke VShell/ v/$2/ i/protocol $1/ cpe:/a:vandyke:vshell:$2/
match ssh m|^SSH-([\d.]+)-([\w.]+) \(beta\) VShell\r?\n| p/VanDyke VShell/ v/$2 beta/ i/protocol $1/ cpe:/a:vandyke:vshell:$2:beta/
match ssh m|^SSH-([\d.]+)-(\d[-.\w]+) sshlib: WinSSHD (\d[-.\w]+)\r?\n| p/Bitvise WinSSHD/ v/$3/ i/sshlib $2; protocol $1/ o/Windows/ cpe:/a:bitvise:winsshd:$3/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-(\d[-.\w]+) sshlib: WinSSHD\r?\n| p/Bitvise WinSSHD/ i/sshlib $2; protocol $1; server version hidden/ o/Windows/ cpe:/a:bitvise:winsshd/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) sshlib: sshlibSrSshServer ([\w._-]+)\r\n| p/SrSshServer/ v/$3/ i/sshlib $2; protocol $1/
match ssh m|^SSH-([\d.]+)-([\w._-]+) sshlib: GlobalScape\r?\n| p/GlobalScape CuteFTP sshd/ i/sshlib $2; protocol $1/ o/Windows/ cpe:/a:globalscape:cuteftp/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w.-]+)_sshlib GlobalSCAPE\r\n| p/GlobalScape CuteFTP sshd/ i/sshlib $2; protocol $1/ o/Windows/ cpe:/a:globalscape:cuteftp/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w.-]+)_sshlib Globalscape\r\n| p/GlobalScape EFT sshd/ i/sshlib $2; protocol $1/ o/Windows/ cpe:/a:globalscape:eft_server/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) sshlib: EdmzSshDaemon ([\w._-]+)\r\n| p/EdmzSshDaemon/ v/$3/ i/sshlib $2; protocol $1/
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: WinSSHD ([\w._-]+)\r\n| p/Bitvise WinSSHD/ v/$3/ i/FlowSsh $2; protocol $1/ o/Windows/ cpe:/a:bitvise:winsshd:$3/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: WinSSHD ([\w._-]+): free only for personal non-commercial use\r\n| p/Bitvise WinSSHD/ v/$3/ i/FlowSsh $2; protocol $1; non-commercial use/ o/Windows/ cpe:/a:bitvise:winsshd:$3/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: WinSSHD: free only for personal non-commercial use\r\n| p/Bitvise WinSSHD/ i/FlowSsh $2; protocol $1; non-commercial use/ o/Windows/ cpe:/a:bitvise:winsshd/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: Bitvise SSH Server \(WinSSHD\) ([\w._-]+): free only for personal non-commercial use\r\n| p/Bitvise WinSSHD/ v/$3/ i/FlowSsh $2; protocol $1; non-commercial use/ o/Windows/ cpe:/a:bitvise:winsshd:$3/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: Bitvise SSH Server \(WinSSHD\) ([\w._-]+)\r\n| p/Bitvise WinSSHD/ v/$3/ i/FlowSsh $2; protocol $1/ o/Windows/ cpe:/a:bitvise:winsshd:$3/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-([\w._-]+) FlowSsh: Bitvise SSH Server \(WinSSHD\) \r\n| p/Bitvise WinSSHD/ i/FlowSsh $2; protocol $1/ o/Windows/ cpe:/a:bitvise:winsshd/ cpe:/o:microsoft:windows/a
# Cisco VPN 3000 Concentrator
# Cisco VPN Concentrator 3005 - Cisco Systems, Inc./VPN 3000 Concentrator Version 4.0.1.B Jun 20 2003
match ssh m|^SSH-([\d.]+)-OpenSSH\r?\n$| p/OpenSSH/ i/protocol $1/ d/terminal server/ cpe:/a:openbsd:openssh/a
match ssh m|^SSH-1\.5-X\r?\n| p/Cisco VPN Concentrator SSHd/ i/protocol 1.5/ d/terminal server/ cpe:/o:cisco:vpn_3000_concentrator_series_software/
match ssh m|^SSH-([\d.]+)-NetScreen\r?\n| p/NetScreen sshd/ i/protocol $1/ d/firewall/ cpe:/o:juniper:netscreen_screenos/
match ssh m|^SSH-1\.5-FucKiT RootKit by Cyrax\r?\n| p/FucKiT RootKit sshd/ i/**BACKDOOR** protocol 1.5/ o/Linux/ cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-2\.0-dropbear_([-\w.]+)\r?\n| p/Dropbear sshd/ v/$1/ i/protocol 2.0/ o/Linux/ cpe:/a:matt_johnston:dropbear_ssh_server:$1/ cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-2\.0-dropbear\r\n| p/Dropbear sshd/ i/protocol 2.0/ o/Linux/ cpe:/a:matt_johnston:dropbear_ssh_server/ cpe:/o:linux:linux_kernel/a
match ssh m|^Access to service sshd from [-\w_.]+@[-\w_.]+ has been denied\.\r\n| p/libwrap'd OpenSSH/ i/Access denied/ cpe:/a:openbsd:openssh/
match ssh m|^SSH-([\d.]+)-FortiSSH_([\d.]+)\r?\n| p/FortiSSH/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-cryptlib\r?\n| p/APC AOS cryptlib sshd/ i/protocol $1/ o/AOS/ cpe:/o:apc:aos/a
match ssh m|^SSH-([\d.]+)-([\d.]+) Radware\r?\n$| p/Radware Linkproof SSH/ v/$2/ i/protocol $1/ d/terminal server/
match ssh m|^SSH-2\.0-1\.0 Radware SSH \r?\n| p/Radware sshd/ i/protocol 2.0/ d/firewall/
match ssh m|^SSH-([\d.]+)-Radware_([\d.]+)\r?\n| p/Radware sshd/ v/$2/ i/protocol $1/ d/firewall/
match ssh m|^SSH-1\.5-By-ICE_4_All \( Hackers Not Allowed! \)\r?\n| p/ICE_4_All backdoor sshd/ i/**BACKDOOR** protocol 1.5/
match ssh m|^SSH-2\.0-mpSSH_([\d.]+)\r?\n| p/HP Integrated Lights-Out mpSSH/ v/$1/ i/protocol 2.0/ cpe:/h:hp:integrated_lights-out/
match ssh m|^SSH-2\.0-Unknown\r?\n| p/Allot Netenforcer OpenSSH/ i/protocol 2.0/
match ssh m|^SSH-2\.0-FrSAR ([\d.]+) TRUEX COMPT 32/64\r?\n| p/FrSAR truex compt sshd/ v/$1/ i/protocol 2.0/
match ssh m|^SSH-2\.0-(\d{8,12})\r?\n| p/Netpilot config access/ v/$1/ i/protocol 2.0/
match ssh m|^SSH-([\d.]+)-RomCliSecure_([\d.]+)\r?\n| p/Adtran Netvanta RomCliSecure sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-2\.0-APSSH_([\w.]+)\r?\n| p/APSSHd/ v/$1/ i/protocol 2.0/
match ssh m|^SSH-2\.0-Twisted\r?\n| p/Kojoney SSH honeypot/ i/protocol 2.0/ cpe:/a:twistedmatrix:twisted/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.]+)\r?\n.*aes256|s p/Kojoney SSH honeypot/ i/Pretending to be $2; protocol $1/
match ssh m|^SSH-2\.0-Mocana SSH\r\n| p/Mocana embedded SSH/ i/protocol 2.0/
match ssh m|^SSH-2\.0-Mocana SSH \r?\n| p/Mocana embedded SSH/ i/protocol 2.0/
match ssh m|^SSH-2\.0-Mocana SSH ([\d.]+)\r?\n| p/Mocana NanoSSH/ v/$1/ i/protocol 2.0/
match ssh m|^SSH-1\.99-InteropSecShell_([\d.]+)\r?\n| p/InteropSystems SSH/ v/$1/ i/protocol 1.99/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-WeOnlyDo(?:-wodFTPD)? ([\d.]+)\r?\n| p/WeOnlyDo sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-WeOnlyDo-([\d.]+)\r?\n| p/WeOnlyDo sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-2\.0-PGP\r?\n| p/PGP Universal sshd/ i/protocol 2.0/ cpe:/a:pgp:universal_server/
match ssh m|^SSH-([\d.]+)-libssh[_-]([-\w.]+)\r?\n| p/libssh/ v/$2/ i/protocol $1/ cpe:/a:libssh:libssh:$2/
match ssh m|^SSH-([\d.]+)-libssh\n| p/libssh/ i/protocol $1/ cpe:/a:libssh:libssh/
match ssh m|^SSH-([\d.]+)-HUAWEI-VRP([\d.]+)\r?\n| p/Huawei VRP sshd/ i/protocol $1/ d/router/ o/VRP $2/ cpe:/o:huawei:vrp:$2/
match ssh m|^SSH-([\d.]+)-HUAWEI-UMG([\d.]+)\r?\n| p/Huawei Unified Media Gateway sshd/ i/model: $2; protocol $1/ cpe:/h:huawei:$2/
# Huawei 6050 WAP
match ssh m|^SSH-([\d.]+)-HUAWEI-([\d.]+)\r?\n| p/Huawei WAP sshd/ v/$2/ i/protocol $1/ d/WAP/
match ssh m|^SSH-([\d.]+)-VRP-([\d.]+)\r?\n| p/Huawei VRP sshd/ i/protocol $1/ d/router/ o/VRP $2/ cpe:/o:huawei:vrp:$2/
match ssh m|^SSH-([\d.]+)-lancom\r?\n| p/lancom sshd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-xxxxxxx\r?\n| p|Fortinet VPN/firewall sshd| i/protocol $1/ d/firewall/
match ssh m|^SSH-([\d.]+)-AOS_SSH\r?\n| p/AOS sshd/ i/protocol $1/ o/AOS/ cpe:/o:apc:aos/a
match ssh m|^SSH-([\d.]+)-RedlineNetworksSSH_([\d.]+) Derived_From_OpenSSH-([\d.])+\r?\n| p/RedLineNetworks sshd/ v/$2/ i/Derived from OpenSSH $3; protocol $1/
match ssh m|^SSH-([\d.]+)-DLink Corp\. SSH server ver ([\d.]+)\r?\n| p/D-Link sshd/ v/$2/ i/protocol $1/ d/router/
match ssh m|^SSH-([\d.]+)-FreSSH\.([\d.]+)\r?\n| p/FreSSH/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Neteyes-C-Series_([\d.]+)\r?\n| p/Neteyes C Series load balancer sshd/ v/$2/ i/protocol $1/ d/load balancer/
match ssh m|^SSH-([\d.]+)-IPSSH-([\d.]+)\r?\n| p|Cisco/3com IPSSHd| v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-DigiSSH_([\d.]+)\r?\n| p/Digi CM sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-0 Tasman Networks Inc\.\r?\n| p/Tasman router sshd/ i/protocol $1/ d/router/
match ssh m|^SSH-([\d.]+)-([\w.]+)rad\r?\n| p/Rad Java SFTPd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\d.]+) in DesktopAuthority ([\d.]+)\r?\n| p/DesktopAuthority OpenSSH/ v/$2/ i/DesktopAuthority $3; protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-NOS-SSH_([\d.]+)\r?\n| p/3Com WX2200 or WX4400 NOS sshd/ v/$2/ i/protocol $1/ d/WAP/
match ssh m|^SSH-1\.5-SSH\.0\.1\r?\n| p/Dell PowerConnect sshd/ i/protocol 1.5/ d/power-device/
match ssh m|^SSH-([\d.]+)-Ingrian_SSH\r?\n| p/Ingrian SSH/ i/protocol $1/ d/security-misc/
match ssh m|^SSH-([\d.]+)-PSFTPd PE\. Secure FTP Server ready\r?\n| p/PSFTPd sshd/ i/protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-BlueArcSSH_([\d.]+)\r?\n| p/BlueArc sshd/ v/$2/ i/protocol $1/ d/storage-misc/
match ssh m|^SSH-([\d.]+)-Zyxel SSH server\r?\n| p/ZyXEL ZyWALL sshd/ i/protocol $1/ d/security-misc/ o/ZyNOS/ cpe:/o:zyxel:zynos/
match ssh m|^SSH-([\d.]+)-paramiko_([\w._-]+)\r?\n| p/Paramiko Python sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-USHA SSHv([\w._-]+)\r?\n| p/USHA SSH/ v/$2/ i/protocol $1/ d/power-device/
match ssh m|^SSH-([\d.]+)-SSH_0\.2\r?\n$| p/3com sshd/ v/0.2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-CoreFTP-([\w._-]+)\r?\n| p/CoreFTP sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-RomSShell_([\w._-]+)\r\n| p/AllegroSoft RomSShell sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-IFT SSH server BUILD_VER\n| p/Sun StorEdge 3511 sshd/ i/protocol $1; IFT SSH/ d/storage-misc/
match ssh m|^Could not load hosy key\. Closing connection\.\.\.$| p/Cisco switch sshd/ i/misconfigured/ d/switch/ o/IOS/ cpe:/a:cisco:ssh/ cpe:/o:cisco:ios/a
match ssh m|^Could not load host key\. Closing connection\.\.\.$| p/Cisco switch sshd/ i/misconfigured/ d/switch/ o/IOS/ cpe:/a:cisco:ssh/ cpe:/o:cisco:ios/a
match ssh m|^SSH-([\d.]+)-WS_FTP-SSH_([\w._-]+)(?: FIPS)?\r\n| p/WS_FTP sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/a:ipswitch:ws_ftp:$2/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-http://www\.sshtools\.com J2SSH \[SERVER\]\r\n| p/SSHTools J2SSH/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-DraySSH_([\w._-]+)\n\n\rNo connection is available now\. Try again later!$| p/DrayTek Vigor 2820 ADSL router sshd/ v/$2/ i/protocol $1/ d/broadband router/ cpe:/h:draytek:vigor_2820/a
match ssh m|^SSH-([\d.]+)-DraySSH_([\w._-]+)\n| p/DrayTek Vigor ADSL router sshd/ v/$2/ i/protocol $1/ d/broadband router/
match ssh m|^SSH-([\d.]+)-Pragma FortressSSH ([\d.]+)\n| p/Pragma Fortress SSH Server/ v/$2/ i/protocol $1/ o/Windows/ cpe:/a:pragmasys:fortress_ssh_server:$2/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-SysaxSSH_([\d.]+)\r\n| p/Sysax Multi Server sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/a:sysax:multi_server:$2/ cpe:/o:microsoft:windows/a
# CP-7900G and 8961
match ssh m|^SSH-([\d.]+)-1\.00\r\n$| p/Cisco IP Phone sshd/ i/protocol $1/ d/VoIP phone/
match ssh m|^SSH-([\d.]+)-Foxit-WAC-Server-([\d.]+ Build \d+)\n| p/Foxit WAC Server sshd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-ROSSSH\r\n| p/MikroTik RouterOS sshd/ i/protocol $1/ d/router/ o/Linux/ cpe:/o:linux:linux_kernel/a cpe:/o:mikrotik:routeros/
match ssh m|^SSH-([\d.]+)-3Com OS-([\w._-]+ Release \w+)\n| p/3Com switch sshd/ v/$2/ i/protocol $1/ d/switch/ o/Comware/ cpe:/o:3com:comware/
match ssh m|^SSH-([\d.]+)-3Com OS-3Com OS V([\w._-]+)\n| p/3Com switch sshd/ v/$2/ i/protocol $1/ d/switch/ o/Comware/ cpe:/o:3com:comware/
match ssh m|^SSH-([\d.]+)-XXXX\r\n| p/Cyberoam firewall sshd/ i/protocol $1/ d/firewall/
match ssh m|^SSH-([\d.]+)-xxx\r\n| p/Cyberoam UTM firewall sshd/ i/protocol $1/ d/firewall/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)-HipServ\n| p/Seagate GoFlex NAS device sshd/ v/$2/ i/protocol $1/ d/storage-misc/
match ssh m|^SSH-([\d.]+)-xlightftpd_release_([\w._-]+)\r\n| p/Xlight FTP Server sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Serv-U_([\w._-]+)\r\n| p/Serv-U SSH Server/ v/$2/ i/protocol $1/ cpe:/a:serv-u:serv-u:$2/
match ssh m|^SSH-([\d.]+)-CerberusFTPServer_([\w._-]+)\r\n| p/Cerberus FTP Server sshd/ v/$2/ i/protocol $1/ cpe:/a:cerberusftp:ftp_server:$2/
match ssh m|^SSH-([\d.]+)-CerberusFTPServer_([\w._-]+) FIPS\r\n| p/Cerberus FTP Server sshd/ v/$2/ i/protocol $1; FIPS/ cpe:/a:cerberusftp:ftp_server:$2/
match ssh m|^SSH-([\d.]+)-SSH_v2\.0@force10networks\.com\r\n| p/Force10 switch sshd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Data ONTAP SSH ([\w._-]+)\n| p/NetApp Data ONTAP sshd/ v/$2/ i/protocol $1/ cpe:/a:netapp:data_ontap/
match ssh m|^SSH-([\d.]+)-SSHTroll| p/SSHTroll ssh honeypot/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-AudioCodes\n| p/AudioCodes MP-124 SIP gateway sshd/ i/protocol $1/ d/VoIP adapter/ cpe:/h:audiocodes:mp-124/
match ssh m|^SSH-([\d.]+)-WRQReflectionForSecureIT_([\w._-]+) Build ([\w._-]+)\r\n| p/WRQ Reflection for Secure IT sshd/ v/$2 build $3/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Nand([\w._-]+)\r\n| p/Nand sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-SSHD-CORE-([\w._-]+)-ATLASSIAN([\w._-]*)\r\n| p/Apache Mina sshd/ v/$2-ATLASSIAN$3/ i/Atlassian Stash; protocol $1/ cpe:/a:apache:sshd:$2/
# Might not always be Atlassian
match ssh m|^SSH-([\d.]+)-SSHD-UNKNOWN\r\n| p/Apache Mina sshd/ i/Atlassian Bitbucket; protocol $1/ cpe:/a:apache:sshd/
match ssh m|^SSH-([\d.]+)-GerritCodeReview_([\w._-]+) \(SSHD-CORE-([\w._-]+)\)\r\n| p/Apache Mina sshd/ v/$3/ i/Gerrit Code Review $2; protocol $1/ cpe:/a:apache:sshd:$3/
match ssh m|^SSH-([\d.]+)-SSHD-CORE-([\w._-]+)\r\n| p/Apache Mina sshd/ v/$2/ i/protocol $1/ cpe:/a:apache:sshd:$2/
match ssh m|^SSH-([\d.]+)-Plan9\r?\n| p/Plan 9 sshd/ i/protocol $1/ o/Plan 9/ cpe:/o:belllabs:plan_9/a
match ssh m|^SSH-2\.0-CISCO_WLC\n| p/Cisco WLC sshd/ d/remote management/
match ssh m|^SSH-([\d.]+)-([\w._-]+) sshlib: ([78]\.\d+\.\d+\.\d+)\r\n| p/MoveIT DMZ sshd/ v/$3/ i/sshlib $2; protocol $1/
match ssh m|^SSH-([\d.]+)-Adtran_([\w._-]+)\r\n| p/Adtran sshd/ v/$2/ i/protocol $1/ o/AOS/ cpe:/o:adtran:aos/
# Axway SecureTransport 1.5 ssh (too generic? --ed.)
match ssh m|^SSH-([\d.]+)-SSHD\r\n| p/Axway SecureTransport sshd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-DOPRA-([\w._-]+)\n| p/Dopra Linux sshd/ v/$2/ i/protocol $1/ o/Dopra Linux/ cpe:/o:huawei:dopra_linux/
match ssh m|^SSH-([\d.]+)-AtiSSH_([\w._-]+)\r\n| p/Allied Telesis sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-CrushFTPSSHD\r\n| p/CrushFTP sftpd/ i/protocol $1/ cpe:/a:crushftp:crushftp/
# Probably not version 5
match ssh m|^SSH-([\d.]+)-CrushFTPSSHD_5\r\n| p/CrushFTP sftpd/ i/protocol $1/ cpe:/a:crushftp:crushftp/
match ssh m|^SSH-([\d.]+)-srtSSHServer_([\w._-]+)\r\n| p/South River Titan sftpd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/a:southrivertech:titan_ftp_server:$2/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-WRQReflectionforSecureIT_([\w._-]+) Build (\d+)\r\n| p/Attachmate Reflection for Secure IT sshd/ v/$2/ i/Build $3; protocol $1/ cpe:/a:attachmate:reflection_for_secure_it:$2/
match ssh m|^SSH-([\d.]+)-Maverick_SSHD\r\n| p/Maverick sshd/ i/protocol $1/ cpe:/a:sshtools:maverick_sshd/
match ssh m|^SSH-([\d.]+)-WingFTPserver\r\n| p/Wing FTP Server sftpd/ i/protocol $1/ cpe:/a:wingftp:wing_ftp_server/
match ssh m|^SSH-([\d.]+)-mod_sftp/([\w._-]+)\r\n| p/ProFTPD mod_sftp/ v/$2/ i/protocol $1/ cpe:/a:proftpd:proftpd:$2/
match ssh m|^SSH-([\d.]+)-mod_sftp\r\n| p/ProFTPD mod_sftp/ i/protocol $1/ cpe:/a:proftpd:proftpd/
match ssh m|^SSH-([\d.]+)--\n| p/Huawei VRP sshd/ i/protocol $1/ o/VRP/ cpe:/o:huawei:vrp/
# name is not hostname, but configurable service name
match ssh m|^SSH-([\d.]+)-SSH Server - ([^\r\n]+)\r\n\0\0...\x14|s p/Ice Cold Apps SSH Server (com.icecoldapps.sshserver)/ i/protocol $1; name: $2/ o/Android/ cpe:/a:ice_cold_apps:ssh_server/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-([\d.]+)-SSH Server - sshd\r\n| p/SSHelper sshd (com.arachnoid.sshelper)/ i/protocol $1/ o/Android/ cpe:/a:arachnoid:sshelper/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a
match ssh m|^SSH-([\d.]+)-ConfD-([\w._-]+)\r\n| p/ConfD sshd/ v/$2/ i/protocol $1/ cpe:/a:tail-f:confd:$2/
match ssh m|^SSH-([\d.]+)-SERVER_([\d.]+)\r\n| p/FoxGate switch sshd/ v/$2/ i/protocol $1/
match ssh m|^SSH-2\.0-Server\r\n| p/AirTight WIPS sensor sshd/ i/protocol 2.0/
match ssh m|^SSH-([\d.]+)-EchoSystem_Server_([\w._-]+)\r\n| p/EchoSystem sshd/ v/$2/ i/protocol $1/ cpe:/a:echo360:echosystem:$2/
match ssh m|^SSH-([\d.]+)-FileCOPA\r\n| p/FileCOPA sftpd/ i/protocol $1/ o/Windows/ cpe:/a:intervations:filecopa/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-PSFTPd\. Secure FTP Server ready\r\n| p/PSFTPd/ i/protocol $1/ o/Windows/ cpe:/a:pleis:psftpd/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-NA_([\d.]+)\r\n| p/HP Network Automation/ v/$2/ i/protocol $1/ cpe:/a:hp:network_automation:$2/
match ssh m|^SSH-([\d.]+)-Comware-([\d.]+)\r?\n| p/HP Comware switch sshd/ v/$2/ i/protocol $1/ o/Comware/ cpe:/o:hp:comware:$2/
match ssh m|^SSH-([\d.]+)-SecureLink SSH Server \(Version ([\d.]+)\)\r\n| p/SecureLink sshd/ v/$2/ i/protocol $1/ cpe:/a:securelink:securelink:$2/
match ssh m|^SSH-([\d.]+)-WeOnlyDo-WingFTP\r\n| p/WingFTP sftpd/ i/protocol $1/ cpe:/a:wftpserver:wing_ftp_server/
match ssh m|^SSH-([\d.]+)-MS_(\d+\.\d\d\d)\r\n| p/Microsoft Windows IoT sshd/ v/$2/ i/protocol $1/ o/Windows 10 IoT Core/ cpe:/o:microsoft:windows_10:::iot_core/
match ssh m|^SSH-([\d.]+)-elastic-sshd\n| p/Elastic Hosts emergency SSH console/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-ZTE_SSH\.([\d.]+)\n| p|ZTE router/switch sshd| v/$2/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-SilverSHielD\r\n| p/SilverSHielD sshd/ i/protocol $1/ o/Windows/ cpe:/a:extenua:silvershield/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-XFB\.Gateway ([UW]\w+)\n| p/Axway File Broker (XFB) sshd/ i/protocol $1/ o/$2/ cpe:/a:axway:file_broker/
match ssh m|^SSH-([\d.]+)-CompleteFTP[-_]([\d.]+)\r\n| p/CompleteFTP sftpd/ v/$2/ i/protocol $1/ o/Windows/ cpe:/a:enterprisedt:completeftp:$2/ cpe:/o:microsoft:windows/a
match ssh m|^SSH-([\d.]+)-moxa_([\d.]+)\r\n| p/Moxa sshd/ v/$2/ i/protocol $1/ d/specialized/
match ssh m|^SSH-([\d.]+)-OneSSH_([\w.]+)\n| p/OneAccess OneSSH/ v/$2/ i/protocol $1/ cpe:/a:oneaccess:onessh:$1/
match ssh m|^SSH-([\d.]+)-AsyncSSH_(\d[\w.-]+)\r\n| p/AsyncSSH sshd/ v/$2/ i/protocol $1/ cpe:/a:ron_frederick:asyncssh:$2/
match ssh m|^SSH-([\d.]+)-ipage FTP Server Ready\r\n| p/iPage Hosting sftpd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-ArrayOS\n| p/Array Networks sshd/ i/protocol $1/ o/ArrayOS/ cpe:/o:arraynetworks:arrayos/
match ssh m|^SSH-([\d.]+)-SC123/SC143 CHIP-RTOS V([\d.]+)\r\n| p/Dropbear sshd/ i/protocol $1/ o/IPC@CHIP-RTOS $2/ cpe:/a:matt_johnston:dropbear_ssh_server/ cpe:/o:beck-ipc:chip-rtos:$2/
match ssh m|^SSH-([\d.]+)-Syncplify\.me\r\n| p/Syncplify.me Server sftpd/ i/protocol $1/ cpe:/a:syncplify:syncplify.me_server/
# Always 0.48 with static key. Dropbear, maybe?
match ssh m|^SSH-([\d.]+)-SSH_(\d[\d.]+)\r\n| p/ZyXEL embedded sshd/ v/$2/ i/protocol $1/ d/broadband router/
match ssh m|^SSH-([\d.]+)-TECHNICOLOR_SW_([\d.]+)\n| p/Technicolor SA sshd/ v/$2/ i/protocol $1/ d/broadband router/
match ssh m|^SSH-([\d.]+)-BoKS_SSH_([\d.]+)\r\n| p/FoxT BoKS sshd/ v/$2/ i/protocol $1/ cpe:/a:fox_technologies:boks:$2/
match ssh m|^SSH-([\d.]+)-Gitblit_v([\d.]+) \(SSHD-CORE-([\d.]+)-NIO2\)\r\n| p/Apache Mina sshd/ v/$3/ i/Gitblit $2; protocol $1/ cpe:/a:apache:sshd:$3/ cpe:/a:jamesmoger:gitblit:$2/
match ssh m|^SSH-([\d.]+)-LXSSH_([\d.]+)\n| p/MRV LX sshd/ v/$2/ i/protocol $1/ d/terminal server/ cpe:/a:mrv:lx_system_software:$2/
match ssh m|^SSH-([\d.]+)-GoAnywhere([\d.]+)\r\n| p/GoAnywhere MFT sshd/ v/$2/ i/protocol $1/ cpe:/a:linoma:goanywhere_mft:$2/
match ssh m|^SSH-([\d.]+)-SFTP Server\r\n| p/IBM Sterling B2B Integrator sftpd/ i/protocol $1/ cpe:/a:ibm:sterling_b2b_integrator/
match ssh m|^SSH-([\d.]+)-SSH\r\n| p/McAfee Web Gateway sshd/ i/protocol $1/ cpe:/a:mcafee:web_gateway/
# Not sure if this is a version number or protocol number or what.
match ssh m|^SSH-([\d.]+)-SSH_2\.0\n| p/Digi PortServer TS MEI sshd/ i/protocol $1/ d/terminal server/
match ssh m|^SSH-([\d.]+)-CISCO_WLC\r\n| p/Cisco Wireless LAN Controller sshd/ i/protocol $1/
match ssh m|^SSH-([\d.]+)-Teleport (\d[\w._-]+)\n| p/Gravitational Teleport sshd/ v/$2/ i/protocol $1/ cpe:/a:gravitational:teleport:$2/
match ssh m|^SSH-([\d.]+)-Teleport\n| p/Gravitational Teleport sshd/ v/2.7.0 or later/ i/protocol $1/ cpe:/a:gravitational:teleport/
match ssh m|^SSH-([\d.]+)-Axway\.Gateway\r\n| p/Axway API Gateway sshd/ i/protocol $1/ cpe:/a:axway:api_gateway/
match ssh m|^SSH-([\d.]+)-CPS_SSH_ID_([\d.]+)\r\n| p/CyberPower sshd/ v/$2/ i/protocol $1/ d/power-device/
match ssh m|^SSH-([\d.]+)-1\r\n| p/Clavister cOS sshd/ i/protocol $1/ d/firewall/

# FortiSSH uses random server name - match an appropriate length, then check for 3 dissimilar character classes in a row.
# Does not catch everything, but ought to be pretty good.
match ssh m%^SSH-([\d.]+)-(?=[\w._-]{5,15}\r?\n$).*(?:[a-z](?:[A-Z]\d|\d[A-Z])|[A-Z](?:[a-z]\d|\d[a-z])|\d(?:[a-z][A-Z]|[A-Z][a-z]))% p/FortiSSH/ i/protocol $1/ cpe:/o:fortinet:fortios/
# This might be bad, but we'll try it: 5 consonants in a row, but not including "SSH"
match ssh m|^SSH-([\d.]+)-(?=[\w._-]{5,15}\r?\n$)(?!.*[sS][sS][hH]).*[b-df-hj-np-tv-xzB-DF-HJ-NP-TV-XZ]{5}| p/FortiSSH/ i/protocol $1/ cpe:/o:fortinet:fortios/


# VMware has a buch of different auth settings so this gets messy
match vmware-auth m|^220 VMware Authentication Daemon Version (\d[-.\w]+).*\r\n530 Please login with USER and PASS\.\r\n|s p/VMware Authentication Daemon/ v/$1/
match vmware-auth m=^220 VMware Authentication Daemon Version (\d[-.\w]+), ServerDaemonProtocol:(SOAP|IPC), MKSDisplayProtocol:VNC= p/VMware Authentication Daemon/ v/$1/ i/Uses VNC, $2/

match ssl/vmware-auth m|^220 VMware Authentication Daemon Version (\d[-.\w]+): SSL Required\r\n| p/VMware Authentication Daemon/ v/$1/
match ssl/vmware-auth m|^220 VMware Authentication Daemon Version (\d[-.\w]+): SSL [rR]equired, MKSDisplayProtocol:VNC(?: ,)? \r\n| p/VMware Authentication Daemon/ v/$1/ i/Uses VNC/
match ssl/vmware-auth m=^220 VMware Authentication Daemon Version (\d[-.\w]+): SSL Required, ServerDaemonProtocol:(SOAP|IPC), MKSDisplayProtocol:VNC= p/VMware Authentication Daemon/ v/$1/ i/Uses VNC, $2/

match vmware-aam m|^\0\0..\x01\0\0\0\x03\x03\x01\x03@\xe4\x01\x02\0..\0\xfe\xff\xff\xff\0\0d\0\0..\0\xfe\xff\xff\xff\0\0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\0\x8fd\0\0...\t\0\0\0\0.\0\0\0.\0\0\0..\0\0.\0\0\0\x6b\x1f\0\0\0\0\0\0\x02\0\0\0\x8fc\0\0...\t\0\0\0\0\.\0\0\0\0\0\0\0| p/VMware Automated Availability Manager/

match vnc m|^RFB 003\.00(\d)\n$| p/VNC/ i/protocol 3.$1/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0\x1aToo many security failures$| p/VNC/ i/protocol 3.$1; Locked out/
match vnc m|^RFB 003.130\n$| p/VNC/ i/unofficial protocol 3.130/
match vnc m|^RFB 003\.88[89]\n$| p/Apple remote desktop vnc/ o/Mac OS X/ cpe:/o:apple:mac_os_x/a
match vnc m|^RFB 000\.000\n$| p/Ultr@VNC Repeater/ cpe:/a:ultravnc:repeater/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0jServer license key is missing, invalid or has expired\.\nVisit http://www\.realvnc\.com to purchase a licence\.| p/RealVNC/ i/Unlicensed; protocol 3.$1/ cpe:/a:realvnc:realvnc/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0nVNC Server license key is missing, invalid or has expired\.\nVisit http://www\.realvnc\.com to purchase a license\.| p/RealVNC/ i/Unlicensed; protocol 3.$1/ cpe:/a:realvnc:realvnc/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0\x8cLa licencia de VNC Server no se ha activado correctamente\.\n\nNo se permitir\xc3\xa1n conexiones hasta que se aplique una clave de licencia v\xc3\xa1lida\.| p/RealVNC/ i/Unlicensed; protocol 3.$1; Spanish/ cpe:/a:realvnc:realvnc::::es/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0MTrial period has expired\.\nVisit http://www\.realvnc\.com to purchase a license\.| p/RealVNC/ i/Trial expired; protocol 3.$1/ cpe:/a:realvnc:realvnc/
match vnc m|^RFB 004\.000\n| p/RealVNC Personal/ i/protocol 4.0/ cpe:/a:realvnc:realvnc:::personal/
match vnc m|^RFB 004\.001\n| p/RealVNC Enterprise/ i/protocol 4.1/ cpe:/a:realvnc:realvnc:::enterprise/
match vnc m|^RFB 005\.000\n| p/RealVNC Enterprise/ v/5.3 or later/ i/protocol 5.0/ cpe:/a:realvnc:realvnc:::enterprise/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0:Unable to open license file: No such file or directory \(2\)| p/RealVNC Enterprise Edition/ i/protocol 3.$1/ cpe:/a:realvnc:realvnc:::enterprise/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0jServer license key is missing, invalid or has expired\.\nVisit http://www\.realvnc\.com to purchase a license\.| p/RealVNC Enterprise/ i/protocol 3.$1/ cpe:/a:realvnc:realvnc:::enterprise/
match vnc m|^RFB 103\.006\n| p/Microsoft Virtual Server remote control/ o/Windows/ cpe:/a:microsoft:virtual_server/ cpe:/o:microsoft:windows/a
match vnc m|^ISD 001\.000\n$| p/iTALC/
match vnc m|^.{27}\x16\x20\xe4\xb0\x95\x63\x29\x78\xdb\x6e\x35\x92$|s p/Ultr@VNC/ cpe:/a:ultravnc:ultravnc/
match vnc m|^RFB 240\.6\n\0\x02$| p/BRemote VNC/
match vnc m|^RFB 009\.123\n| p/ATEN KVM-over-IP VNC/ d/remote management/
match vnc m|^RFB 003\.00(\d)\n\0\0\0\0\0\0\0kVNC Server is not licensed correctly\.\n\nConnections will be prohibited until a valid license key is applied\.| p/RealVNC/ i/unlicensed; protocol 3.$1/ cpe:/a:realvnc:realvnc/

softmatch vnc m|RFB \d\d(\d)\.\d\d\d\n| i/protocol $1/

# vsftpd (Very Secure FTP Daemon) 1.0.0 on linux with custom ftpd_banner
# We'll have to see if this match is unique enough ... no, it is not enough...
# Turning match line into softmatch because it can match much more than just
# vsftpd and WU-FTPD... (Brandon)
# Adding this back as a hard match or we'll never stop getting vsftpd
# submissions. (David)
# See version 2.0.8 note under TCP Help probe.
match ftp m|^220 .*\r\n530 Please login with USER and PASS\.\r\n530 Please login with USER and PASS\.\r\n| p/vsftpd (before 2.0.8) or WU-FTPD/ cpe:/a:vsftpd:vsftpd/

match ftp-proxy m|^220 .*FTP Proxy\r\n500 Syntax error, command unrecognized\.\r\n| p/Cisco Web Security ftp proxy/ cpe:/h:cisco:web_security_appliance/
softmatch http m|^HTTP/1.[01] \d\d\d|
match http m|^HTTP\/[0-9\.]+\s+[0-9]{3}\b.*$| p/HTTP/

match rsync m|^@RSYNCD: (\d+)| i/protocol version $1/
# Synology Network Backup Service (rsync backup)
match rsync m|^@ERROR: protocol startup error\n|

##############################NEXT PROBE##############################
# TLSv1.2 ClientHello probe. TLS implementations may choose to ignore (close
# silently) incompatible ClientHello messages like the one in SSLSessionReq.
# This one should be widely compatible, and if we avoid adding non-ssl service
# matches here, we can continue to upgrade it (bytes 10 and 11 and the ranges
# in the match lines)
Probe TCP TLSSessionReq q|\x16\x03\0\0\x69\x01\0\0\x65\x03\x03U\x1c\xa7\xe4random1random2random3random4\0\0\x0c\0/\0\x0a\0\x13\x009\0\x04\0\xff\x01\0\0\x30\0\x0d\0,\0*\0\x01\0\x03\0\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\x03\x03\x03\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\x05\x03\x05\x02|
rarity 1
# Remove 3388 and 3389 if the ssl/ms-wbt-server match below doesn't catch stuff well enough.
ports 443,444,465,636,989,990,992,993,994,995,1241,1311,2252,3388,3389,33890,3390,33900,4433,4444,5061,6679,6697,8443,8883,9001
fallback GetRequest

# SSLv3 - TLSv1.3 ServerHello
match ssl m|^\x16\x03[\0-\x04]..\x02\0\0.\x03[\0-\x03]|s
# SSLv3 - TLSv1.3 Alert
match ssl m|^\x15\x03[\0-\x04]\0\x02[\x01\x02].$|s
match autonomic-mrad m|^\x1b\[2J\x1b\[2J\r\n\r\nAutonomic Controls MRAD Bridge version (\d[\w.]+) Release\.\r\nMore info found on the Web http://www\.Autonomic-Controls\.com\r\n\r\nType '\?' for help or 'help <command>' for help on <command>\.\r\n\r\n\r\nError: Unknown command '\x01'\.\r\nError: Unknown command '\x03'\.\r\n| p/Autonomic Controls MRAD Bridge/ v/$1/ d/media device/
match iperf3 m|^\t$|
match imap m|^\* OK.*| p/IMAP/
match ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x1f\x08\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02.\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x124\0$| p/Microsoft Terminal Services/ o/Windows XP/ cpe:/o:microsoft:windows_xp/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x12\x34\0$| p/Microsoft Terminal Services/ o/Windows 2003/ cpe:/o:microsoft:windows_2003/a
match ms-wbt-server m|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$| p/Microsoft Terminal Service/ i/Used with Netmeeting, Remote Desktop, Remote Assistance/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a



##############################NEXT PROBE##############################
# SSLv2-compatible ClientHello, 39 ciphers offered.
# Will elicit a ServerHello from most SSL implementations, apart from those
# that are TLSv1-only or SSLv3-only. As it comes after the SSLv3 probe
# (SSLSessionReq), its only added value is the detection of SSLv2-only servers.
# SSLv2-only servers are rare so this probe has a high rarity.
Probe TCP SSLv23SessionReq q|\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98|

rarity 8
ports 443,444,465,548,636,989,990,992,993,994,995,1241,1311,2000,4433,4444,5550,7210,7272,8009,8194,8443,9001
fallback GetRequest

# SSLv2 ServerHello
match ssl m|^..\x04\0.\0\x02|s p/SSLv2/

# TLSv1 ServerHello, compatible with SSLv2:
match ssl m|^\x16\x03\x01..\x02...\x03\x01|s p/TLSv1/

# SSLv3 ServerHello, compatible with SSLv2:
match ssl m|^\x16\x03\0..\x02...\x03\0|s p/SSLv3/

# SSLv3 - TLSv1.3 ServerHello
match ssl m|^\x16\x03[\0-\x04]..\x02\0\0.\x03[\0-\x03]|s

# SSLv3 - TLSv1.2 Alert
match ssl m|^\x15\x03[\0-\x04]\0\x02[\x01\x02].$|s

match iperf3 m|^\t$|
match misys-loaniq m|^\0\0\0#sJ\0\0\0\0\0\0#\0\0\0Invalid time string: \n\0\0\0\0#sJ\0\0\0\0\0\0#\0\0\0Invalid time string: \n\0\0\0\0#sJ\0\0\0\0\0\0#\0\0\0Invalid time string: \n\0\0\0\0#sJ\0\0\0\0\0\0#\0\0\0Invalid time string: \n\0\0\0..sJ\0\0\0\0\0\0..\0\0\n Misys Loan IQ ([\w._-]+) \(Server\)\n Build  : for Windows using Oracle \(built: (\w\w\w \d\d \d\d\d\d_\d\d:\d\d:\d\d) \([\w._-]+@[\w._-]+-C:\\[^)]*\)\)\n Patch Info : \[(?:[\w._-]+(?:, )?)+\]\n\n Environment name: \w+ Prime - \w+\n    ADMCP Primary node: \w+;  Secondary node: \w+; Portdaem Port = (\d+)\n\n Current time: [^\n]*\n On: \w+  \([\w._-]+\)\n OS: (Microsoft Windows[^\n]*)\n MEMORY  \(Tot/Free\) : ([\d.]+) / ([\d.]+) MB\n\n Last Logger Start : [^\n]*\n L$| p/Misys Loan IQ/ v/$1/ i|built $2; portdaem port $3; free memory $6/$5 MB; $4| o/Windows/ cpe:/o:microsoft:windows/a
match misys-loaniq m|^\0\0@\0tJ\0\0\0\0\0\0\0@\0\0\n Misys Loan IQ ([\w._-]+) \(Server\)\n Build  : for Windows using Oracle \(built: (\w\w\w \d\d \d\d\d\d_\d\d:\d\d:\d\d) \([\w._-]+@[\w._-]+-C:\\[^)]*\)\)\n Patch Info : \[\]\n\n Environment name: \w+ \w+\n    ADMCP Primary node: \w+;  Secondary node: \w+; Portdaem Port = (\d+)\n\n Current time: [^\n]*\n On: \w+  \([\w._-]+\)\n OS: (Microsoft Windows[^\n]*)\n MEMORY  \(Tot/Free\) : ([\d.]+) / ([\d.]+) MB\n| p/Misys Loan IQ/ v/$1/ i|built $2; portdaem port $3; free memory $6/$5 MB; $4| o/Windows/ cpe:/o:microsoft:windows/a


##############################NEXT PROBE##############################
# Kerberos AS_REQ with realm NM, server name krbtgt/NM, missing client name.
Probe TCP Kerberos q|\0\0\0\x71\x6a\x81\x6e\x30\x81\x6b\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a\xa4\x81\x5e\x30\x5c\xa0\x07\x03\x05\0\x50\x80\0\x10\xa2\x04\x1b\x02NM\xa3\x17\x30\x15\xa0\x03\x02\x01\0\xa1\x0e\x30\x0c\x1b\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8\x17\x30\x15\x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02|
rarity 5
ports 88

# MIT 1.2.8
match kerberos-sec m=^\0\0\0[\x88-\x8a]~\x81[\x86-\x88]0\x81[\x83-\x85]\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa2\x11\x18\x0f\d{14}Z\xa4\x11\x18\x0f(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\xa5[\x03-\x05]\x02(?:\x03...|\x02..|\x01.)\xa6\x03\x02\x01\x06\xa9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM\xab\(\x1b&Client not found in Kerberos database\0$=s p/MIT Kerberos/ v/1.2/ i/server time: $1-$2-$3 $4:$5:$6Z/ cpe:/a:mit:kerberos:5-1.2/

# OS X 10.6.2; MIT 1.3.5, 1.6.3, 1.7.
match kerberos-sec m=^\0\0\0[\x6d-\x6f]~[\x6b-\x6d]0[\x69-\x6b]\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa2\x11\x18\x0f\d{14}Z\xa4\x11\x18\x0f(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\xa5[\x03-\x05]\x02(?:\x03...|\x02..|\x01.)\xa6\x03\x02\x01\x06\xa9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM\xab\x0e\x1b\x0cNULL_CLIENT\0$=s p/MIT Kerberos/ v/1.3 - 1.8/ i/server time: $1-$2-$3 $4:$5:$6Z/ cpe:/a:mit:kerberos:5-1/

# Heimdal 1.0.1-5ubuntu4
match kerberos-sec m=^\0\0\0[\x62-\x64]~[\x60-\x62]0[\x5e-\x60]\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\xa5[\x03-\x05]\x02(?:\x03...|\x02..|\x01.)\xa6\x03\x02\x01<\xa9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM\xab\x16\x1b\x14No client in request$=s p/Heimdal Kerberos/ i/server time: $1-$2-$3 $4:$5:$6Z/ cpe:/a:heimdal:kerberos/

match kerberos-sec m=^\0\0\0[\x4a-\x4c]~[\x48-\x4a]0[\x46-\x48]\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\xa5[\x03-\x05]\x02(?:\x03...|\x02..|\x01.)\xa6\x03\x02\x01D\xa9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM$=s p/Microsoft Windows Kerberos/ i/server time: $1-$2-$3 $4:$5:$6Z/ o/Windows/ cpe:/a:microsoft:kerberos/ cpe:/o:microsoft:windows/a
match kerberos-sec m=^\0\0\0[\x79-\xf0]\0[\x79-\xf0]\0\x01\0\0~[\x71-\xe8]0[\x69-\x80]\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\xa5[\x03-\x05]\x02(?:\x03...|\x02..|\x01.)\xa6\x03\x02\x01<\xa9.\x1b.([\w.-]+)\xaa\x1d0\x1b\xa0\x03\x02\x01\0\xa1\x140\x12\x1b\x06kadmin\x1b\x08changepw\xac#\x04!\0\x01Request length was inconsistent=s p/MIT Kerberos/ i/OpenWRT; server time: $1-$2-$3 $4:$5:$6Z; realm: $7/ cpe:/a:mit:kerberos/

match netradio m%^@(?:NETRADIO|MAIN|SYS):[A-Z0-9]+=% p/Yamaha Net Radio/ d/media device/

match qemu-vlan m|^\0\0\0qj\x81n0\x81k\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa4\x81\^0\\\xa0\x07\x03\x05\0P\x80\0\x10\xa2\x04\x1b\x02NM\xa3\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z| p/QEMU VLAN listener/ cpe:/a:qemu:qemu/

match sap-gui m|^\0\0\0\x0e\*\*DPTMMSG\*\*\0\0\xf8| p/SAP Gui Dispatcher/ cpe:/a:sap:gui/

softmatch smpp m|^\0\0\0\x10\x80\0\0\0\0\0\0\x03....$|s

# SMB Negotiate Protocol
##############################NEXT PROBE##############################
Probe TCP SMBProgNeg q|\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0|
rarity 4
ports 42,88,135,139,445,660,1025,1027,1031,1112,3006,3900,5000,5009,5432,5555,5600,7461,9102,9103,18182,27000-27010

match anynet-sna m|^\0\0MF\xff\xf3MBr\0\0\0\0\x08\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1\.0\0\x02MICROSOFT NETWORKS 1\.03\0\x02MICROSOFT NETWORKS 3\.0\0\x02LANMAN1\.0\0\x02LM1\.2X002\0\x02Samba\0\x02NT LANMAN 1\.0\0\x02NT LM 0$| p/AnyNet SNA/
match as-signon m|^\0\0\0\x18\xffSMBr\0\0\0\0\x08\x01@\0\x04\xf0\0\0\x01\0\x03$| p/IBM Client Tools signon/

match nomachine-nx m|^...................................................................................................\x00\x00\x00\x00\x00.\x00\x00\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00...\x84\x8e\x7f\x00\x00......\x00\x00......\x00\x00......\x00\x00......\x00\x00...\x00\x00\x00\x00\x00....\x8e\x7f\x00\x00......\x00\x00......\x00\x00...\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00......\x00\x00...\x00\x00\x00\x00\x00....\x00\x00\x00\x00......\x00\x00...\x84\x8e\x7f\x00\x00......\x00\x00......\x00\x00....\x00\x00\x00\x00......\x00\x00...\x00\x00\x00\x00\x00.....\x7f\x00\x00......\x00\x00.\xfe\x7c\x17..\x00\x00......\x00\x00...\x00\x00\x00\x00\x00......\x00\x00......\x00\x00....\x00\x00\x00\x00......\x00\x00...\x00\x00\x00\x00\x00......\x00\x00\x40.....\x00\x00......\x00\x00......\x00\x00......\x00\x00.....\x7f\x00\x00...\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00...\x00\x00\x00\x00\x00....\x8e\x7f\x00\x00......\x00\x00...| p/NoMachine NX remote administration/

match airport-admin m|^acpp\0.\0.....\0\0\0\x01| p/Apple AirPort or Time Capsule admin/

match afarianotify m|^\0\0\x017<AfariaNotify version=\"([\w._-]+)\"><Client name=\"\w+\" GUID=\"{[0-9A-F-]+}\"/><Message type=\"Response\" value=\"Client Error\"><Description><!\[CDATA\[\[\w\w\w \w\w\w \d\d \d\d:\d\d:\d\d \d\d\d\d\]\t\[Unrecognized notification header\]:\t\[Expected\]:<AfariaNotify version=\r\n\r\n\]\]></Description></Message></AfariaNotify>| p/Sybase Afaria/ v/$1/ i/Abbott i-STAT blood analyzer/

match ajp13 m|^\0\0\0\x01\0\x0cUnauthorized| p/Oracle Containers for J2EE/ i/unauthorized/ cpe:/a:oracle:containers_for_j2ee/

match bmc-tmart m=^\x15uBMC TM ART Version ([\w._-]+, Build \d+ from [\d-]+), Copyright \? [\d-]+ BMC Software, Inc\. \| All Rights Reserved\.= p/BMC Transaction Management Application Response Time/ v/$1/ cpe:/a:bmc:transaction_management_application_response_time:$1/

match brassmonkey m|^\x08\0\0\0\0\0\x08\x01\0\0\t\0$| p/Brass Monkey controller service/

match byond m|^\0\0\0\x02\0\0$| p/BYOND game platform/

match caigos-conductus m|^\0\0\0\0\0\0\0=r\0\0\0\0\0\0\0\xd8\x97%\x01\x13\0\0\0CONDUCTUS_PG([\w._-]+)\x1a\0\0\0unbekannter Code: 19240920$| p/Conductus/ v/$1/ i/Caigos GIS/
match caigos-pactor m|^\0\0\0\0\0\0\0:r\0\0\0\0\0\0\0\xe8EU\x04\x10\0\0\0PACTOR_PG([\w._-]+)\x1a\0\0\0unbekannter Code: 72697320$| p/Pactor/ v/$1/ i/Caigos GIS/
match caigos-fundus m|^\0\0\0\0\0\0\0;r\0\0\0\0\0\0\0h\xd52\t\x10\0\0\0FUNDUS_PG([\w._-]+)\x1b\0\0\0unbekannter Code: 154326376$| p/Fundus/ v/$1/ i/Caigos GIS/
match caigos-paratus m|^\0\0\0\0\0\0\0;r\0\0\0\0\0\0\0XL\)\x01\x11\0\0\0PARATUS_PG([\w._-]+)\x1a\0\0\0unbekannter Code: 19483736$| p/Paratus/ v/$1/ i/Caigos GIS/
match caigos-conspectus m|^\0\0\0\0\0\0\0>r\0\0\0\0\0\0\0\xf8\x926\x01\x14\0\0\0CONSPECTUS_PG([\w._-]+)\x1a\0\0\0unbekannter Code: 20353784$| p/Conspectus/ v/$1/ i/Caigos GIS/

match digitalwatchdog m|^\x01\0\0\0\0\0\0\(PSPROTOCOL\0\0\0\0\0\0\xa0\0\0\x01\0\0\0\x0c\0\0\0\0\0\0\0\0\xe0\0\0\x04\0\0\0\0\0\0\0\0| p/Digital Watchdog IP camera unknown service/ d/webcam/
# Need more matches. Same response to Kerberos, runs on 1489 and 1490(secure)
match docbroker m|^\0\0\0\x080\x06\x02\x01\0\x02\x01i| p/Documentum Content Server/ cpe:/a:emc:documentum_content_server/
match fastobjects-db m|^\xce\xfa\x01\0\x16\0\0\0\0\0\0\x003\xf6\0\0\0\0\0\0\0\0$| p/Versant FastObjects database/

# Flexlm might be too general: -Doug
match flexlm m|^W.-60\0|s p/FlexLM license manager/
match flexlm m|^W.\0\0\0\0|s p/FlexLM license manager/

match greenplum m|^E\0\0\0\x83SFATAL\0C0A000\0Munsupported frontend protocol 3923\.19778: server supports 1\.0 to 3\.0\0Fpostmaster\.c\0L2504\0RProcessStartupPacket\0\0| p/Greenplum database/

match h2 m|^\x52\x00\x00\x00\x08\x00\x00\x00\x03$| p/H2 database/

match honeywell-hscodbcn m|^\0\0\0\x02\0\x03$| p/Honeywell hscodbcn power management server/

match http m|^HTTP/1\.0 503 OK\r\nContent-Type: text/html\r\n\r\nBusy$| p/D-Link DI-524 WAP http config/ d/WAP/ cpe:/h:dlink:di-524/
match http m|^HTTP/1\.1 414 Request URI Too Long\r\nServer: Catwalk\r\nDate: .*\r\nContent-Length: 0\r\nConnection: close\r\n\r\n$| p/Catwalk httpd/ i/Canon imageRUNNER printer/ d/printer/
match http m|^HTTP\/[0-9\.]+\s+[0-9]{3}\b.*$| p/HTTP/

match iperf3 m|^\t$|

# Need more examples of this one -Doug
match kerberos-sec m|^.*Internal KDC error, contact administrator|s p/Shishi kerberos-sec/

match libvirt-rpc m|^\0\0\0\xb8\xffSMBr\0\0\0\0\x08\x01@\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0'\0\0\0\x07\0\0\0\x01\0\0\0\x30Cannot find program -11317950 version 1912602624\0\0\0\x02\0\0\0\0\0\0\0\x01\0\0\0\x02%s\0\0\0\0\0\x01\0\0\0\x30Cannot find program -11317950 version 1912602624\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0| p/libvirt RPC/ cpe:/a:redhat:libvirt/

match lorex-monitor m|^\0\0\x01\x01@\n\0\x08\x80\0\x82\0L\xb8..\xff\xff\xff\xff\0\0\0\0$|s p/Lorex security camera monitor/ d/webcam/

match metatrader m|^A$| p/MetaTrader Data Center/

# Longhorn
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\n\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\x03\0|s p/Microsoft Windows Longhorn microsoft-ds/ o/Windows/ cpe:/o:microsoft:windows/a
# Windows XP SP1
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\n\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\0\0|s p/Microsoft Windows XP microsoft-ds/ o/Windows XP/ cpe:/o:microsoft:windows_xp/a
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfd\xf3\0\0|s p/Microsoft Windows 2000 microsoft-ds/ o/Windows 2000/ cpe:/o:microsoft:windows_2000/a
# Microsoft Windows 2003 or 2008
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04.\0\0\0\0\x01\0\0\0\0\0\xfd\xf3\x01\0|s p/Microsoft Windows 2003 or 2008 microsoft-ds/ o/Windows/ cpe:/o:microsoft:windows_server_2003/a
# Microsoft Windows 2000 Server
# Microsoft Windows 2000 Server SP4
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.[}2]\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfd[\xe3\xf3]\0\0|s p/Microsoft Windows 2000 microsoft-ds/ o/Windows 2000/ cpe:/o:microsoft:windows_2000/a
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0|s p/Microsoft Windows Server 2008 R2 - 2012 microsoft-ds/ o/Windows Server 2008 R2 - 2012/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xf3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows Server 2008 R2 - 2012 microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\n\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows 7 - 10 microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\n\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0|s p/Microsoft Windows 7 - 10 microsoft-ds/ o/Windows/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0.{21}(.*)\0\0(.*)\0\0|s p/Microsoft Windows 7 - 10 microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0|s p/Microsoft Windows 7 - 10 microsoft-ds/ o/Windows/ cpe:/o:microsoft:windows/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows Server 2008 R2 microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows_server_2008:r2/a
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\x10\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows Embedded Standard microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows/a
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\x10\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\0\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows XP Embedded microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows_xp/a
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\x0a\0\x01\0\x04\x11\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows Vista Embedded microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows_vista/a

match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.\x05\0\x01\0\x04\x11\0\0\0\0\x01\0\xad\x05\0\0|s p|IBM OS/400 microsoft-ds| o|OS/400| cpe:/o:ibm:os_400/a

# Xerox WorkCentre Pro c3545 and Xerox DocumentCentre 425
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x81\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\r\x03\0|s p/Xerox printer microsoft-ds/ d/printer/
match microsoft-ds m|^\0\0\0\x61\xffSMBr\0\0\0\0\x88\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x06\0\x02\x0a\0\x01\0....\xff\xff\x00\x00....\0\x03\0\0\0|s p/Xerox WorkCentre 5225 printer microsoft-ds/ d/printer/ cpe:/h:xerox:workcentre_5225/a
# FujiXerox ApeosPort-IV C4470
# Xerox WorkCentre 5225
match microsoft-ds m|^\0\0\0\x61\xffSMBr\0\0\0\0\x88\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x06\0\x02\x0a\0\x01\0\x04\x11\0\0\xff\xff\0\0....\0\x03\0\0..........\x08\x1c\0........\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0$|s p/Xerox printer microsoft-ds/ d/printer/
match microsoft-ds m|^\0\0\0\x3d\xffSMBr\0\0\0\0\x88\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0..\0\0\x01\0\r\x04\0\x01\0\xfc\x032\0\x03\0\0\0\0\0\0\0......\0\0\0\0\0\0|s p/Edimax PS-1206P print server smbd/ d/print server/
match microsoft-ds m|^\0\0\0\x4d\xffSMBr\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0..\0\0\x01\0\x11\x07\0\x02\x02\0\x01\0\xfc\x7f\0\0\0\0\x01\0\x01\0\0\0\0\x02\0\0..........\x08\x08\0\0\0\0\0\0\0\0\0|s p/Sharp MX-M350N printer smbd/ d/printer/ cpe:/h:sharp:mx-m350n/a
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x81\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0..\0\0\x01\0\x11\x06\0\x03\x7f\0\x01\0\xff\xff\0\0\xff\xff\0\0\0\0\0\0\xfd\xb3\0\0..........\x08\x22\0........((?:\w\0)+)\0\0((?:\w\0)+)\0\0$|s p/EMC Celerra NAS device smbd/ i/Primary domain: $P(1)/ h/$P(2)/
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x98\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\x40\x06\0\0\x01\0\x11\x07\0\x03\x01\0\x01\0\0\x10\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\0\0..........\x00\x34\0W\0O\0R\0K\0G\0R\0O\0U\0P\0\0\0H\0O\0M\0E\0U\0S\0E\0R\0-\0.\0.\0.\0.\0.\0.\0\0\0|s p/Dionaea honeypot smbd/
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x98\x02\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\x11\x07\0\x032\0\x01\0\x04\x41\0\0\0\0\x01\0\0\0\0\0\xfc\xc0\0\x80..........\0..................\x60\x5f\x06\x06\+\x06\x01\x05\x05\x02\xa0U0S\xa0\+0\)\x06\t\*\x86H\x86\xf7\x12\x01\x02\x02\x06\x05\+\x05\x01\x05\x02\x06\t\*\x86H\x82\xf7\x12\x01\x02\x02\x06\n\+\x06\x01\x04\x01\x827\x02\x02\n\xa3\$0\"\xa0 \x1b\x1e[\w._-]+/([\w._-]+)@$|s p/Likewise smbd/ h/$1/
# key was \xd7\xd7\xd8\xd8\xd8\xd8\xd8\xd9
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\n\0\x01\0<\[\0\0\0\0\x01\0\0\0\0\0\\\0\0\0........\0\0\x08\x08\0........| p/HP Officejet Pro 8600 printer smbd/ d/printer/ cpe:/h:hp:officejet_pro_8600/a
# key was 4 bytes repeated
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x88\x03\xc0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x02\x01\0\x01\0\xff\xff\0\0\0\0\x01\0\0\0\0\0\}\xa2\0\0..........\x08\x08\0........|s p/Arcadyan ARV752DPW22 (Vodafone EasyBox 803A) WAP smbd/ d/WAP/ cpe:/h:arcadyan:arv752dpw22/
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x88\x01H\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\n\0\x01\0\0\0\x01\0\0\0\x01\0\0\0\0\0\x7c\xe0\0\0..........\x08\x08\0........|s p/Epson WF-2650 printer smbd/ d/printer/ cpe:/h:epson:wf-2650/a
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\n\0\x01\0\xec\xfa\0\0\0\0\x01\0\0\0\0\0\x7c \0\0..........\x08\x08\0........|s p/Apple Time Capsule smbd/ d/storage-misc/
match microsoft-ds m|^\0...\xffSMBr\0\0\0\0\x88C@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\xff\xff\x01\0\x04A\0\0\x04A\0\0....\xfc\x02\0\0.{21}((?:..)+)\0\0((?:..)+)\0\0| p/Acopia ARX switch smbd/ i/workgroup: $P(1)/ d/storage-misc/ h/$P(2)/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x02\x01\0\x01\0h\x0b\0\0\xff\xff\0\0\0\0\0\0\x07\x02\0\0\0\0\0\0\0\0\0\0..\x08\x08\0\0\0\0\0\0\0\0\0| p/Fujitsu Storagebird LAN smbd/ d/storage-misc/ cpe:/h:fujitsu:storagebird_lan/
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01H\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\n\0\x01\0\0\0\x01\0\0\0\x01\0\0\0\0\0\x7c \0\0..........\x08\x08| p/Epson printer smbd/ d/printer/
match microsoft-ds m|^\0\0\0a\xffSMBr\0\0\0\0\x80\0{16}@\x06\0\0\x01\0\x11\x07\0\x03\x01\0\x14\0@\x1e\0\0\xff\xff\0\0....\x14\x02\0{10}..\x08\x1c\0.{8}((?:(?!\0\0).)+?)\0\0| p/Canon Pixma printer smbd/ i/workgroup: $P(1)/ d/printer/

# Microsoft Windows XP SP1
# Windows 2000
match msrpc m|^\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$|s p/Microsoft Windows RPC/ o/Windows/ cpe:/o:microsoft:windows/a
# Microsoft Windows 2000
# samba-2.2.7-5.8.0 on RedHat 8
# samba-2.2.7a-8.9.0 on Red Hat Linux 7.x
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x06\0.*\W([-_.\w]+)\0$|s p/Samba smbd/ i/workgroup: $1/ cpe:/a:samba:samba/
# Samba 2.999+3.0.alpha21-5 on Linux
# Samba 3.0.0rc4-Debian
# Samba 4.1.6-ubuntu
# Samba 3.6.x on FreeBSD
# Samba 3.0.x based SMB implementation by Apple
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x88..\0\0[-\w. ]*\0+@\x06\0\0\x01\0\x11\x06\0.{42}(.*)\0\0(.*)\0\0$|s p/Samba smbd/ v/3.X - 4.X/ i/workgroup: $P(1)/ h/$P(2)/ cpe:/a:samba:samba/
# The line below may no longer be required and seems to miss the first capture on test systems
match netbios-ssn m=^\0\0\0.\xffSMBr\0\0\0\0\x88..\0\0[-\w. ]*\0+@\x06\0\0\x01\0\x11\x06\0.*(?:[^\0]|[^_A-Z0-9-]\0)((?:[-\w]\0){2,50})=s p/Samba smbd/ v/3.X - 4.X/ i/workgroup: $P(1)/ cpe:/a:samba:samba/
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x88..\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x06\0..\0\x01\0..\0\0...\0..\0\0|s p/Samba smbd/ v/3.X - 4.X/ cpe:/a:samba:samba/
# Samba 2.2.8a on Linux 2.4.20
match netbios-ssn m|^\x83\0\0\x01\x81$| p/Samba smbd/ cpe:/a:samba:samba/
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x88..\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x01\xff\xff\0\0$|s p/Samba smbd/ v/4.6.2/ cpe:/a:samba:samba:4.6.2/
# DAVE 4.1 enhanced windows networks services for Mac on Mac OS X
match netbios-ssn m|^\0\0\0.\xffSMBr\x02\0Y\0\x98\x01.\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\0\x07\0|s p/Thursby DAVE Windows filesharing/ i/Runs on Macintosh systems/ o/Mac OS/ cpe:/o:apple:mac_os/a
# Windows Session Service - 139/tcp - Formerly Window 98 match, actually matches Win 98 through Windows 8 / 2012 R2
match netbios-ssn m|^\x83\0\0\x01\x8f$| p/Microsoft Windows netbios-ssn/ o/Windows/ cpe:/o:microsoft:windows/a
# Netware might just be using Samba?
match netbios-ssn m|^\0\0\0M\xffSMBr\0\0\0\0\x80\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x032\0\x01\0\xff\xff\0\0\0\0\x01\0| p/NetWare 6 SMB Services/ o/NetWare/ cpe:/o:novell:netware:6/
# Network Appliance ONTAP 6.3.3 netbios-ssn
match netbios-ssn m=^\0\0\0.\xffSMBr\0\0\0\0\x98\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.*(?:[^\0]|[^_A-Z0-9-]\0)((?:[-\w]\0){2,50})=s p/Netapp ONTAP smbd/ i/workgroup: $P(1)/ cpe:/a:netapp:data_ontap/
match netbios-ssn m|^\0\0\0.\xffSMBr\0\0\0\0\x98\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.*\W([-_.\w]+)\0$| p/Netapp ONTAP smbd/ i/workgroup: $1/ cpe:/a:netapp:data_ontap/
match netbios-ssn m|^\0\0\0M\xffSMBr\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x02\x02\0\x01\0\0\x80\0\0\0\0\x01\0\x01\0\0\0\0\x02\0\0| p/Kyocera FS-1030D printer smbd/ d/printer/ cpe:/h:kyocera:fs-1030d/a
match netbios-ssn m|^\x82\0\0\0\n-> doHttp: Connection timeouted!\n\ntelnetd: This system \*IN USE\* via telnet\.\nshell restarted\.\n\x08\x08\x08\x08        \*\*\*  EPSON Network Print Server \(([^)]+)\)  \*\*\*\n\n\x08\x08\x08\x08        \nPassword: | p/Epson print server smbd/ v/$1/ d/print server/
match netbios-ssn m|^\0\0\0M\xffSMBr\0\0\0\0\x98. \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x03\x32\0\x01\0....\x00\x00\x01\x00....\xf4\xc2\0\0|s p/IOGear GMFPSU22W6 print server smbd/ d/print server/ cpe:/h:iogear:gmfpsu22w6/a
# match netbios-ssn m|^\0\0\0M\xffSMBr\0\0\0\0\x98\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x032\0\x01\0\x04A\0\0\0\0\x01\0 \0\0\0\xf4\xc2\0\0\x80\x1e\xdd\x8b\xe7\?\xca\x01 \xfe\x08\x08\0z~\xc7\*\xc9\x1f\xd3\x9b"
match netbios-ssn m|^\0\0\0M\xffSMBr\0\0\0\0\x98\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0\x02\x01\0\x01\0\xff\xff\0\0\xff\xff\0\0\0\0\0\0\x01\x02\0\0| p/Brother MFC-820CW printer smbd/ d/printer/ cpe:/h:brother:mfc-820cw/a
match netbios-ssn m|^\0\0\0G\xffSMBr\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\r\x04\0\0\0\xa0\x05\x02\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0WORKGROUP\0$| p/Citizen CLP-521 printer smbd/ d/printer/ cpe:/h:citizen:clp-521/
match netbios-ssn m|^\0\0\0G\xffSMBr\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\r\x04\0\0\0\xa0\x05\x02\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0| p/Kyocera Mita KM-1530 printer smbd/ d/printer/ cpe:/h:kyocera:mita_km-1530/a
match netbios-ssn m|^\x82\0\0\0$| p/Konica Minolta bizhub C452 printer smbd/ d/printer/ cpe:/h:konicaminolta:bizhub_c452/

# Too broad, but also gives good info
softmatch microsoft-ds m|^\0\0..\xffSMBr\0\0\0\0[\x80-\xff]..\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11[\x01-\x07]\0.{42}(.*)\0\0(.*)\0\0$|s i/workgroup: $P(1)/ h/$P(2)/
softmatch microsoft-ds m|^\0\0..\xffSMBr\0\0\0\0[\x80-\xff]..\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11[\x01-\x07]\0|s

match remote-volume m|^\0\0\0\x18\xffSMB\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0| p/NetApp Remote Volume protocol/
match netradio m%^@(?:NETRADIO|MAIN|SYS):[A-Z0-9]+=% p/Yamaha Net Radio/ d/media device/

match nightwatchman m|^ACKDONEV\$\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0([\d.]+)\0\0\0| p/1E NightWatchman WakeUp Server/ v/$1/

# HP OpenView Storage Data Protector A.05.10 on Windows 2000
# Hewlett Packard Omniback 4.1 on Windows NT
match omniback m|^\0\0\0.\xff\xfe1\x005\0\0\0 \0\x07\0\x01\0\[\x001\x002\0:\x001\0\]\0\0\0 \0\x07\0\x02\0\[\x002\x000\x000\x003\0\]\0\0\0 |s p/HP OpenView Omniback/ o/Windows/ cpe:/o:microsoft:windows/a
# HP OpenView Storage Data Protector A.05.10 on Linux
match omniback m|^\0\0\0.15\0 \x07\x01\[12:1\]\0 \x07\x02\[2003\]\0 \x07\x051\d+\0 INET\0 ([\w._-]+)\0|s p|HP OpenView Omniback/Data Protector| o/Unix/ h/$1/

match ouman-trend m|^\0\0\0\x05\xffSMBr$| p/Ouman Trend environmental sensor/

#### Match versions based on line numbers in error messages.
# http://seclists.org/nmap-dev/2010/q1/456
# Update like this:
# cd src/backend/postmaster/; git tag -l 'REL*' | while read tag; do git checkout $tag -- postmaster.c; echo $tag:$(grep -n "PG_PROTOCOL_MINOR(PG_PROTOCOL_LATEST))));" postmaster.c) >> lines.txt; done

# The line numbers need to be updated in both the non-Windows and Windows sections

# Amazon Redshift, based on PostgreSQL 8.0.2
# line numbers are distinctly different, as well as the source code path
match postgresql m|^E\0\0\0.SFATAL\0C0A000\0Munsupported frontend protocol 65363\.19778: server supports 1\.0 to 3\.0\0F/home/ec2-user/padb/src/pg/src/backend/postmaster/postmaster\.c\0L2463\0RProcessStartupPacket\0\0$|s p/Amazon Redshift/ v/1.0.1691/ cpe:/a:amazon:redshift:1.0.1691/

# PostgreSQL - Non-Windows platforms
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1287\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/7.4.0 - 7.4.1/ cpe:/a:postgresql:postgresql:7.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1293\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/7.4.2 - 7.4.30/ cpe:/a:postgresql:postgresql:7.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1408\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.0 - 8.0.1/ cpe:/a:postgresql:postgresql:8.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1431\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.2 - 8.0.4/ cpe:/a:postgresql:postgresql:8.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1439\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.7 - 8.0.8/ cpe:/a:postgresql:postgresql:8.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1443\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.9 - 8.0.13/ cpe:/a:postgresql:postgresql:8.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1445\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.6 or 8.0.14 - 8.0.26/ cpe:/a:postgresql:postgresql:8.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1449\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.0/ cpe:/a:postgresql:postgresql:8.1.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1450\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.1/ cpe:/a:postgresql:postgresql:8.1.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1448\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.3 - 8.1.4/ cpe:/a:postgresql:postgresql:8.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1452\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.5 - 8.1.9/ cpe:/a:postgresql:postgresql:8.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1454\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.2 or 8.1.10 - 8.1.23/ cpe:/a:postgresql:postgresql:8.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1432\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.0/ cpe:/a:postgresql:postgresql:8.2.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1437\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.1 - 8.2.4/ cpe:/a:postgresql:postgresql:8.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1440\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.5 - 8.2.19/ cpe:/a:postgresql:postgresql:8.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1441\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.5 or 8.2.20 - 8.2.23/ cpe:/a:postgresql:postgresql:8.0.5/ cpe:/a:postgresql:postgresql:8.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1497\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.0 - 8.3.7/ cpe:/a:postgresql:postgresql:8.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1507\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.8 - 8.3.13/ cpe:/a:postgresql:postgresql:8.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1508\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.14 - 8.3.18/ cpe:/a:postgresql:postgresql:8.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1514\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.19/ cpe:/a:postgresql:postgresql:8.3.19/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1515\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.20 - 8.3.23/ cpe:/a:postgresql:postgresql:8.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1570\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.0/ cpe:/a:postgresql:postgresql:8.4.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1621\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.1 - 8.4.11/ cpe:/a:postgresql:postgresql:8.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1626\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.12/ cpe:/a:postgresql:postgresql:8.4.12/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1627\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.13 - 8.4.19/ cpe:/a:postgresql:postgresql:8.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1622\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.20 - 8.4.22/ cpe:/a:postgresql:postgresql:8.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1666\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.0 - 9.0.7/ cpe:/a:postgresql:postgresql:9.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1671\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.8/ cpe:/a:postgresql:postgresql:9.0.8/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1677\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.9 - 9.0.15/ cpe:/a:postgresql:postgresql:9.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1672\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.16 - 9.0.18/ cpe:/a:postgresql:postgresql:9.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1705\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.19 - 9.0.22/ cpe:/a:postgresql:postgresql:9.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1753\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.23/ cpe:/a:postgresql:postgresql:9.0.23/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1694\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.0 - 9.1.1/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1695\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.2 - 9.1.3/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1700\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.4/ cpe:/a:postgresql:postgresql:9.1.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1706\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.5 - 9.1.11/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1701\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.12 - 9.1.14/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1734\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.15 - 9.1.18/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1803\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.19/ cpe:/a:postgresql:postgresql:9.1.19/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1833\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.20 - 9.1.24/ cpe:/a:postgresql:postgresql:9.1/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1612\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.0 - 9.2.6/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1607\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.7 - 9.2.9/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1640\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.10 - 9.2.13/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1709\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.14/ cpe:/a:postgresql:postgresql:9.2.14/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1739\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.15 - 9.2.16/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1742\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.17/ cpe:/a:postgresql:postgresql:9.2.17/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1746\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.18 - 9.2.19/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1747\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.20 - 9.2.21/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1755\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.22 - 9.2.24/ cpe:/a:postgresql:postgresql:9.2/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1837\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.0 - 9.3.2/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1834\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.3 - 9.3.5/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1872\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.6 - 9.3.9/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1949\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.10/ cpe:/a:postgresql:postgresql:9.3.10/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1979\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.11 - 9.3.12/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1982\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.13/ cpe:/a:postgresql:postgresql:9.3.13/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1849\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.0/ cpe:/a:postgresql:postgresql:9.4.0/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1881\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.1 - 9.4.4/ cpe:/a:postgresql:postgresql:9.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1955\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.5/ cpe:/a:postgresql:postgresql:9.4.5/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1986\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.14 - 9.3.15 or 9.4.6 - 9.4.8/ cpe:/a:postgresql:postgresql:9/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1987\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.16 - 9.3.17/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1994\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.21 - 9.3.25/ cpe:/a:postgresql:postgresql:9.3/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1990\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.9/ cpe:/a:postgresql:postgresql:9.4.9/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2000\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.10/ cpe:/a:postgresql:postgresql:9.4.10/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2001\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.11/ cpe:/a:postgresql:postgresql:9.4.11/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2002\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.12/ cpe:/a:postgresql:postgresql:9.4.12/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2010\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.13 - 9.4.15 or 9.4.22 - 9.4.26/ cpe:/a:postgresql:postgresql:9.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2009\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.16 - 9.4.21, 9.5.20 (Docker apline image)/ cpe:/a:postgresql:postgresql:9.4/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1991\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.0 - 9.5.3/ cpe:/a:postgresql:postgresql:9.5/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L1995\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.18 - 9.3.20 or 9.5.4/ cpe:/a:postgresql:postgresql:9/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2005\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.5/ cpe:/a:postgresql:postgresql:9.5.5/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2006\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.6/ cpe:/a:postgresql:postgresql:9.5.6/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2007\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.7/ cpe:/a:postgresql:postgresql:9.5.7/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2015\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.8 - 9.5.10 or 9.5.17 - 9.5.21/ cpe:/a:postgresql:postgresql:9.5/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2014\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.11 - 9.5.16/ cpe:/a:postgresql:postgresql:9.5/
# 9.6.0 introduced a nonlocalized error message
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2008\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.0 - 9.6.1/ cpe:/a:postgresql:postgresql:9.6/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2009\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.2/ cpe:/a:postgresql:postgresql:9.6.2/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2023\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.3/ cpe:/a:postgresql:postgresql:9.6.3/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2031\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.4 - 9.6.6 or 9.6.13 - 9.6.17/ cpe:/a:postgresql:postgresql:9.6/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2030\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.7 - 9.6.12/ cpe:/a:postgresql:postgresql:9.6/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2065\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/10.0 - 10.1 or 10.8 - 10.12/ cpe:/a:postgresql:postgresql:10/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2064\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/10.2 - 10.7/ cpe:/a:postgresql:postgresql:10/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2015\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/11.0 - 11.2/ cpe:/a:postgresql:postgresql:11/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2016\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/11.3 - 11.7/ cpe:/a:postgresql:postgresql:11/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2060\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/12.0 - 12.2/ cpe:/a:postgresql:postgresql:12/

# PostgreSQL - Docker image - most docker images have the same error message as the release version, these do not.
# Seems images build after the move to from Alpine 3.10 to 3.11 have changed line numbers.
# PR where this behavior starts: https://github.com/docker-library/postgres/pull/657
match postgresql m|^E\0\0\0.SFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2004\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.25 - 9.4.26/ i/Docker alpine image/ cpe:/a:postgresql:postgresql:9.4/ cpe:/a:alpinelinux:alpine_linux:-/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2025\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.16 - 9.6.17/ i/Docker alpine image/ cpe:/a:postgresql:postgresql:9.6/ cpe:/a:alpinelinux:alpine_linux:-/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2059\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/10.11 - 10.12/ i/Docker alpine image/ cpe:/a:postgresql:postgresql:10/ cpe:/a:alpinelinux:alpine_linux:-/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2010\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/11.6 - 11.7/ i/Docker alpine image/ cpe:/a:postgresql:postgresql:11/ cpe:/a:alpinelinux:alpine_linux:-/
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0Fpostmaster\.c\0L2054\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/12.1 - 12.2/ i/Docker alpine image/ cpe:/a:postgresql:postgresql:12/ cpe:/a:alpinelinux:alpine_linux:-/


# PostgreSQL - Windows platforms
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1287\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/7.4.0 - 7.4.1/ o/Windows/ cpe:/a:postgresql:postgresql:7.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1293\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/7.4.2 - 7.4.30/ o/Windows/ cpe:/a:postgresql:postgresql:7.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1408\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.0 - 8.0.1/ o/Windows/ cpe:/a:postgresql:postgresql:8.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1431\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.2 - 8.0.4/ o/Windows/ cpe:/a:postgresql:postgresql:8.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1439\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.7 - 8.0.8/ o/Windows/ cpe:/a:postgresql:postgresql:8.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1443\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.9 - 8.0.13/ o/Windows/ cpe:/a:postgresql:postgresql:8.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1445\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.6 or 8.0.14 - 8.0.26/ o/Windows/ cpe:/a:postgresql:postgresql:8.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1449\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.0/ o/Windows/ cpe:/a:postgresql:postgresql:8.1.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1450\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.1/ o/Windows/ cpe:/a:postgresql:postgresql:8.1.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1448\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.3 - 8.1.4/ o/Windows/ cpe:/a:postgresql:postgresql:8.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1452\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.5 - 8.1.9/ o/Windows/ cpe:/a:postgresql:postgresql:8.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1454\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.1.2 or 8.1.10 - 8.1.23/ o/Windows/ cpe:/a:postgresql:postgresql:8.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1432\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.0/ o/Windows/ cpe:/a:postgresql:postgresql:8.2.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1437\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.1 - 8.2.4/ o/Windows/ cpe:/a:postgresql:postgresql:8.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1440\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.2.5 - 8.2.19/ o/Windows/ cpe:/a:postgresql:postgresql:8.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1441\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.0.5 or 8.2.20 - 8.2.23/ o/Windows/ cpe:/a:postgresql:postgresql:8.0.5/ cpe:/a:postgresql:postgresql:8.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1497\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.0 - 8.3.7/ o/Windows/ cpe:/a:postgresql:postgresql:8.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1507\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.8 - 8.3.13/ o/Windows/ cpe:/a:postgresql:postgresql:8.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1508\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.14 - 8.3.18/ o/Windows/ cpe:/a:postgresql:postgresql:8.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1514\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.19/ o/Windows/ cpe:/a:postgresql:postgresql:8.3.19/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1515\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.3.20 - 8.3.23/ o/Windows/ cpe:/a:postgresql:postgresql:8.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1570\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.0/ o/Windows/ cpe:/a:postgresql:postgresql:8.4.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1621\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.1 - 8.4.11/ o/Windows/ cpe:/a:postgresql:postgresql:8.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1626\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.12/ o/Windows/ cpe:/a:postgresql:postgresql:8.4.12/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1627\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.13 - 8.4.19/ o/Windows/ cpe:/a:postgresql:postgresql:8.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1622\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/8.4.20 - 8.4.22/ o/Windows/ cpe:/a:postgresql:postgresql:8.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1666\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.0 - 9.0.7/ o/Windows/ cpe:/a:postgresql:postgresql:9.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1671\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.8/ o/Windows/ cpe:/a:postgresql:postgresql:9.0.8/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1677\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.9 - 9.0.15/ o/Windows/ cpe:/a:postgresql:postgresql:9.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1672\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.16 - 9.0.18/ o/Windows/ cpe:/a:postgresql:postgresql:9.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1705\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.19 - 9.0.22/ o/Windows/ cpe:/a:postgresql:postgresql:9.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1753\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.0.23/ o/Windows/ cpe:/a:postgresql:postgresql:9.0.23/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1694\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.0 - 9.1.1/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1695\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.2 - 9.1.3/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1700\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.4/ o/Windows/ cpe:/a:postgresql:postgresql:9.1.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1706\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.5 - 9.1.11/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1701\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.12 - 9.1.14/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1734\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.15 - 9.1.18/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1803\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.19/ o/Windows/ cpe:/a:postgresql:postgresql:9.1.19/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1833\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.1.20 - 9.1.24/ o/Windows/ cpe:/a:postgresql:postgresql:9.1/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1612\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.0 - 9.2.6/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1607\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.7 - 9.2.9/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1640\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.10 - 9.2.13/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1709\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.14/ o/Windows/ cpe:/a:postgresql:postgresql:9.2.14/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1739\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.15 - 9.2.16/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1742\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.17/ o/Windows/ cpe:/a:postgresql:postgresql:9.2.17/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1746\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.18 - 9.2.19/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1747\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.20 - 9.2.21/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1755\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.2.22 - 9.2.24/ o/Windows/ cpe:/a:postgresql:postgresql:9.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1837\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.0 - 9.3.2/ o/Windows/ cpe:/a:postgresql:postgresql:9.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1834\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.3 - 9.3.5/ o/Windows/ cpe:/a:postgresql:postgresql:9.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1872\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.6 - 9.3.9/ o/Windows/ cpe:/a:postgresql:postgresql:9.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1949\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.10/ o/Windows/ cpe:/a:postgresql:postgresql:9.3.10/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1849\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.0/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.0/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1881\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.1 - 9.4.4/ o/Windows/ cpe:/a:postgresql:postgresql:9.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1955\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.5/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.5/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1986\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.14 - 9.3.15 or 9.4.6 - 9.4.8/ o/Windows/ cpe:/a:postgresql:postgresql:9/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1987\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.16 - 9.3.17/ o/Windows/ cpe:/a:postgresql:postgresql:9.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1994\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.21 - 9.3.25/ o/Windows/ cpe:/a:postgresql:postgresql:9.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1990\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.9/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.9/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2000\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.10/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.10/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2001\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.11/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.11/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2002\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.12/ o/Windows/ cpe:/a:postgresql:postgresql:9.4.12/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2010\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.13 - 9.4.15 or 9.4.22 - 9.4.26/ o/Windows/ cpe:/a:postgresql:postgresql:9.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2009\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.4.16 - 9.4.21/ o/Windows/ cpe:/a:postgresql:postgresql:9.4/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1991\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.0 - 9.5.3/ o/Windows/ cpe:/a:postgresql:postgresql:9.5/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L1995\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.3.18 - 9.3.20 or 9.5.4/ o/Windows/ cpe:/a:postgresql:postgresql:9/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2005\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.5/ o/Windows/ cpe:/a:postgresql:postgresql:9.5.5/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2006\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.6/ o/Windows/ cpe:/a:postgresql:postgresql:9.5.6/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2007\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.7/ o/Windows/ cpe:/a:postgresql:postgresql:9.5.7/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2015\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.8 - 9.5.10 or 9.5.17 - 9.5.21/ o/Windows/ cpe:/a:postgresql:postgresql:9.5/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2014\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.5.11 - 9.5.16/ o/Windows/ cpe:/a:postgresql:postgresql:9.5/ cpe:/o:microsoft:windows/a
# 9.6.0 introduced a nonlocalized error message
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2008\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.0 - 9.6.1/ o/Windows/ cpe:/a:postgresql:postgresql:9.6/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2009\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.2/ o/Windows/ cpe:/a:postgresql:postgresql:9.6.2/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2023\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.3/ o/Windows/ cpe:/a:postgresql:postgresql:9.6.3/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2031\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.4 - 9.6.6 or 9.6.13 - 9.6.17/ o/Windows/ cpe:/a:postgresql:postgresql:9.6/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2030\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/9.6.7 - 9.6.12/ o/Windows/ cpe:/a:postgresql:postgresql:9.6/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2065\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/10.0 - 10.1 or 10.8 - 10.12/ o/Windows/ cpe:/a:postgresql:postgresql:10/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2064\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/10.2 - 10.7/ o/Windows/ cpe:/a:postgresql:postgresql:10/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2015\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/11.0 - 11.2/ o/Windows/ cpe:/a:postgresql:postgresql:11/ cpe:/o:microsoft:windows/a
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2016\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/11.3 - 11.7/ o/Windows/ cpe:/a:postgresql:postgresql:11/ cpe:/o:microsoft:windows/a
# Unverified: does postgresql 12 have a different error message?
match postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*\0F\.\\src\\backend\\postmaster\\postmaster\.c\0L2060\0RProcessStartupPacket\0\0$|s p/PostgreSQL DB/ v/12.0 - 12.2/ o/Windows/ cpe:/a:postgresql:postgresql:12/ cpe:/o:microsoft:windows/a

# PostgreSQL - Language specific
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst\xc3\xbctztes Frontend-Protokoll 65363\.19778: Server unterst\xc3\xbctzt 1\.0 bis 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/German; Unicode support/ cpe:/a:postgresql:postgresql::::de/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst.{1,2}tztes Frontend-Protokoll 65363\.19778: Server unterst.{1,2}tzt 1\.0 bis 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/German/ cpe:/a:postgresql:postgresql::::de/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\xc3\xa9e de l'interface 65363\.19778: le serveur supporte de 1\.0 \xc3\xa0 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/French; Unicode support/ cpe:/a:postgresql:postgresql::::fr/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\?e de l'interface 65363\.19778 : le serveur supporte de 1\.0 \?\n3\.0\0Fpostmaster\.c\0L1621\0RProcessStartupPacket\0\0| p/PostgreSQL DB/ v/8.4.1 - 8.4.11/ i/French/ cpe:/a:postgresql:postgresql:8.4:::fr/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support\?e de l'interface 65363\.19778 : le serveur supporte de 1\.0 \?\n3\.0\0Fpostmaster\.c\0L1626\0RProcessStartupPacket\0\0$| p/PostgreSQL DB/ v/8.4.12/ i/French/ cpe:/a:postgresql:postgresql:8.4.12:::fr/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support[e\xe9]e de l'interface 65363\.19778: le serveur supporte de 1\.0 [a\xe0] 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/French/ cpe:/a:postgresql:postgresql::::fr/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mprotocole non support\xe9e de l'interface 65363\.19778: le serveur supporte de 1\.0 \xe0 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/French/ cpe:/a:postgresql:postgresql::::fr/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363\.19778 no est..? soportado: servidor soporta 1\.0 hasta 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/Spanish/ cpe:/a:postgresql:postgresql::::es/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363\.19778 no est\? permitido: servidor permite 1\.0 hasta 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/Spanish/ cpe:/a:postgresql:postgresql::::es/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mprotocolo 65363\.19778 n\xe3o \xe9 suportado: servidor suporta 1\.0 a 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/Portuguese/ cpe:/a:postgresql:postgresql::::pt/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mprotocolo do cliente 65363\.19778 n.{4,6} suportado: servidor suporta 1\.0 a 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/Portuguese/ cpe:/a:postgresql:postgresql::::pt/
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M\xd0\xbd\xd0\xb5\xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd0\xbc\xd1\x8b\xd0\xb9 \xd0\xba\xd0\xbb\xd0\xb8\xd0\xb5\xd0\xbd\xd1\x82\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9 \xd0\xbf\xd1\x80\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba\xd0\xbe\xd0\xbb 65363\.19778: \xd1\x81\xd0\xb5\xd1\x80\xd0\xb2\xd0\xb5\xd1\x80 \xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd1\x82 \xd0\xbe\xd1\x82 1\.0 \xd0\xb4\xd0\xbe 3\.0\0Fpostmaster\.c\0L\d+\0|s p/PostgreSQL DB/ i/Russian; Unicode support/ cpe:/a:postgresql:postgresql::::ru/
# Supposed to be Ukrainian? submission came from a .ua domain.
match postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\? 65363\.19778; \?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\?\? 1\.0 - 3\.0 \0Fpostmaster\.c\0L1695\0RProcessStartupPacket\0\0$| p/PostgreSQL DB/ v/9.1.2 - 9.1.3/ cpe:/a:postgresql:postgresql:9.1::uk/
# Korean
match postgresql m|^E\0\0\0\xb1S\xec\xb9\x98| p/PostgreSQL DB/ cpe:/a:postgresql:postgresql/

# PostgreSQL softmatch entries, put all hard matches above this line.
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0MProtocole non support.{1,2}e de l'interface 65363| p/PostgreSQL DB/ i/French/ cpe:/a:postgresql:postgresql::::fr/
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mel protocolo 65363| p/PostgreSQL DB/ i/Spanish/ cpe:/a:postgresql:postgresql::::es/
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Mnicht unterst.*?Frontend-Protokoll 65363\.19778:|s p/PostgreSQL DB/ i/German/ cpe:/a:postgresql:postgresql::::de/
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M\xe3\x83\x95\xe3\x83\xad\xe3\x83\xb3\xe3\x83\x88\xe3\x82\xa8\xe3\x83\xb3\xe3\x83\x89\xe3\x83\x97\xe3\x83\xad\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xab|s p/PostgreSQL DB/ i/Japanese/ cpe:/a:postgresql:postgresql::::ja/
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0Fpostmaster\.c\0|s p/PostgreSQL DB/ cpe:/a:postgresql:postgresql/
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0F\.\\src\\backend\\postmaster\\postmaster\.c\0|s p/PostgreSQL DB/ o/Windows/ cpe:/a:postgresql:postgresql/ cpe:/o:microsoft:windows/a
softmatch postgresql m|^E\0\0\0.S[^\0]+\0C0A000\0Munsupported frontend protocol 65363| p/PostgreSQL DB/ cpe:/a:postgresql:postgresql/

softmatch postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0M.*?65363\.19778.*?1\.0.*?3\.0.*?\0F\.\\src\\backend\\postmaster\\postmaster\.c\0|s p/PostgreSQL DB/ v/9.6.0 or later/ o/Windows/ cpe:/a:postgresql:postgresql/ cpe:/o:microsoft:windows/a
softmatch postgresql m|^E\0\0\0.S[^\0]+\0VFATAL\0C0A000\0Munsupported frontend protocol 65363| p/PostgreSQL DB/ v/9.6.0 or later/ cpe:/a:postgresql:postgresql/

match tcsd m|^\0\0\0\x1c\0\0 \x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0$| p/TCSD daemon/

# Teradata Database 13.10
match teradata m|^\x03\x02\x01\0\0\0\0\0\x004\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f\0\0\0\0\0\0\0\0\0\0\0\0\0\x001\x004\0\0\0\0\0K\x1f\(\0The LAN message Format field is invalid\.| p/Teradata database/

match tng-dts m|^\0\0\0\$sequence_number=\[0\] result=\[-2005\] \0$| p/CA DTS Agent/

# SAP Release: SAP ECC (Enterprise Core Component) 6.0 on Windows 2003
match sap-gui m|^\0\0\0\x0e\*\*DPTMMSG\*\*\0\0\xf8| p/SAP Gui Dispatcher/ cpe:/a:sap:gui/

match serversettingsd m|^\0\0\x004main\0\0\x01\0\0\0\0\x0c\0\0\0\0\0\0\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0quit\xff\xff\xff\xffcrpt$| p/Apple serversettingsd administration daemon/ o/Mac OS X/ cpe:/o:apple:mac_os_x/a
match spotify-login m|^\x01\0$| p/Spotify login server/
match symantec-esm m|^\0\x01[#,]$| p/Symantec Enterprise Security Manager agent/ cpe:/a:symantec:enterprise_security_manager/
# Windows 2000 Server Wins name resolution service
# Windows NT 4.0 Wins
# Windows 2003 WINS service
match wins m|^\0\0\0\x1e\xffS\xad\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0...\0\0\x01\0\0\x81\0\x02|s p/Microsoft Windows Wins/ o/Windows/ cpe:/o:microsoft:windows/a

match sap-its m|^\0\0\0\x0c\x01\x03\0\0\0\0\x07.\0\0\0\0\0\0\x07.Content-Type:  text/html; charset=Windows-\d+\r\n\r\n<!--\r\n This page was created by the \r\n SAP Internet Transaction Server|s p/SAP Internet Transaction Server/

# Likely false-positive?
match routersetup m|^\0\0\0.\xffSMBr\0\0\0\0\x80|s p|Nortel/D-Link router instant setup| d/router/
match tally-census m|^\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\x02\0\0\0\0\0$| p/Tally Collection Client/
match bacula-fd m|^\0\0\0\x152999 Invalid command\n\xff\xff\xff\xfc$| p/Bacula file daemon/
match bacula-sd m|^\0\0\0\x0b3999 No go\n$| p/Bacula storage daemon/
match opsec-ufp m|^\0\0\0\x0c\x01\x01\0\x04r\0\0\0$| p/Check-Point NG firewall/

# Spark 1.5.2
#match spark m|^\0\0\0\0$| p/Apache Spark/ cpe:/a:apache:spark/

match lexmark-objectstore m|\0\0\0\x80<\?xml version=\"1\.0\" encoding=\"UTF-8\"\?>\r\n<exception requestID=\"0\">\r\n  <message>Unable to parse Message\.</message>\r\n</exception>\r\n| p/Lexmark printer objectstore/ d/printer/
match lexmark-objectstore m|^\0\0\0\x7c<\?xml version="1\.0" encoding="UTF-8"\?>\r\n<exception requestID="0">\n<message>Unable to parse Message\.</message>\n</exception>\r\n| p/Lexmark printer objectstore/ d/printer/

match ftp m|^2[23]0 FTP Server Ready\r\n504 Comand length not supported\.\r\n| p/HP JetDirect ftpd/ d/printer/

match vertica m|^V\0\0\x01f:ErrorMsg\nelevel:23\nfilename:/scratch_a/release/vbuild/vertica/Session/ClientSession\.cpp\nlineno:3800\ncaught:SessionRun\nsqlerrcode:16933376\nverticacode:3753\nmessage:Invalid startup packet layout: expected terminator as last byte\ndetail:\nhint:\nlog_message:Invalid startup packet layout: expected terminator as last byte\nlog_detail:\nlog_hint:\ncursorpos:0\n\.\n| p/HP Vertica database/ v/7.0.1/ cpe:/a:hp:vertica:7.0.1/
softmatch vertica m|^V\0\0\x01f:ErrorMsg\nelevel:23\nfilename:/scratch_a/release/vbuild/vertica/Session/ClientSession\.cpp\nlineno:(\d+)\ncaught:SessionRun\nsqlerrcode:16933376\nverticacode:3753\nmessage:Invalid startup packet layout: expected terminator as last byte\ndetail:\nhint:\nlog_message:Invalid startup packet layout: expected terminator as last byte\nlog_detail:\nlog_hint:\ncursorpos:0\n\.\n| p/HP Vertica database/ i/error line $1/ cpe:/a:hp:vertica/

softmatch smpp m|^\0\0\0\x10\x80\0\0\0\0\0\0\x03....$|s


##############################NEXT PROBE##############################
Probe TCP TerminalServer q|\x03\0\0\x0b\x06\xe0\0\0\0\0\0|
rarity 6
ports 515,1028,1068,1503,1720,1935,2040,3388,3389,33890,3390,33900

match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02.\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x12\x34\0$| p/Microsoft Terminal Services/ o/Windows 2003/ cpe:/o:microsoft:windows_2003/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$|s p/Microsoft Terminal Service/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$| p/Microsoft Terminal Service/ i/Used with Netmeeting, Remote Desktop, Remote Assistance/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a

match activefax m|^ActiveFax Server: Es befinden sich insgesamt| p/ActFax Communication ActiveFax/ i/German/
match arcserve-gdd m|^\0\0\x0b\x06\xe0\0\0\0\0\0\0\0\0\0\0\0......\0\0\xa0\xf9\x7f\xee\xfb\x7f\0\0|s p/Arcserve Unified Data Protection Global Deduplication DataStore/ cpe:/a:arcserve:udp/


# TLS 1.0 alert "unexpected message"
match ssl/consul-rpc m|^\x15\x03\x01\0\x02\x02\n| p/HashiCorp Consul RPC/ cpe:/a:hashicorp:consul/
# Cisco video conference device port 1720
match H.323/Q.931 m|^\x03\0\0\x10\x08\x02\x80\0}\x08\x02\x80\xe2\x14\x01\0|

match lineage-ii m|^\x03\0.$| p/Lineage II game server/
# TODO: Dissect this; probably too specific
match lineage-ii m|^G\0\0\x01\0\0\0\xce\x1e\0\0\xce\x1e\0\0\xce\x1e\0\0/\x04\0\x000\0,\x006\0,\x003\x003\x003\x002\0,\x003\x003\x003\x003\0\0\0\x81\x8d\0\0\x81\x8d\0\0\x91\x91\0\0\0\0\0\0\x02\0\0\0| p/L2J Lineage II game server/

# \x03 is queue status command for LPD service.  Should be terminated
# by \n, but apparently some dumb lpds allow \0.  For now I will keep
# 515 in the common ports line, I suppose
match printer m|^no entries\n$| p/Xerox lpd/ d/printer/
match printer m|^SB06D2F0: \xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe1\xa0 no entries\n$| p/Kyocera Mita KM-1530 lpd/ d/printer/
match printer m|^ActiveFax Server: There are \d+ entries in the Faxlist\r\n| p/ActiveFax lpd/
match printer m|^Host Name: ([-\w_.]+)\nPrinter Device: hp LaserJet (\w+)\nPrinter Status: ([^\r\n]+)\n\0\0| p/NetSarang Xlpd/ i/HP LaserJet $2; Status $3/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
match printer m|^Fictive printer queue short information\n$| p/Canon MF4360-4390 lpd/ d/printer/
match printer m|^414A_Citizen_CLP(\d+): \xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe5\x9f\xf0\x18\xe1\xa0 no entries\n$| p/Citizen CLP-$1 lpd/ d/printer/

# Windows 2000 Server
# Windows 2000 Advanced Server
# Windows XP Professional
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$|s p/Microsoft Terminal Service/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$| p/Microsoft Terminal Service/ i/Used with Netmeeting, Remote Desktop, Remote Assistance/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a

match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a

# Need more samples!
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0| p/xrdp/ cpe:/a:jay_sorg:xrdp/
match ms-wbt-server m|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$| p/IBM Sametime Meeting Services/ o/Windows/ cpe:/a:ibm:sametime/ cpe:/o:microsoft:windows/a

match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0| p/VirtualBox VM Remote Desktop Service/ o/Windows/ cpe:/a:oracle:vm_virtualbox/ cpe:/o:microsoft:windows/a

match ms-wbt-server-proxy m|^nmproxy: Procotol byte is not 8\n$| p/nmproxy NetMeeting proxy/

# Semi-open protocol from Adobe: http://www.adobe.com/devnet/rtmp/.
# Some reverse engineering at http://wiki.gnashdev.org/RTMP says the server
# handshake is a 0x03 byte followed by 1536 seeming-random bytes. However
# service scan only gets 900 or 1300 bytes, so just check for as much as
# possible up to 1536.
match rtmp m|^\x03.{899,1536}$|s p/Real-Time Messaging Protocol/

match sybase-monitor m|^\0\x01\0\x08\0\0\x01\0$| p/Sybase Monitor Server/ o/Windows/ cpe:/a:sybase:monitor_server/ cpe:/o:microsoft:windows/a

match trillian m|^.\0\x01.....\0([^\0]+)\0|s p/Trillian MSN Module/ i/Name $1/ o/Windows/ cpe:/a:trillian:trillian/ cpe:/o:microsoft:windows/a

match trustwave m|^control\n   ping\n   endping\nendcontrol\n| p/Trustwave SIEM OE/ cpe:/a:trustwave:siem_oe/



##############################NEXT PROBE##############################
# This is an RDP connection request with the MSTS cookie set. Some RDP
# listeners (with NLA?) only respond to this one.
# This must be sent before TLSSessionReq because Windows RDP will handshake TLS
# immediately and we don't have a way of identifying RDP at that point.
Probe TCP TerminalServerCookie q|\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00|
rarity 7
ports 3388,3389,33890,3390,33900
fallback TerminalServer

# Windows 10
match ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x1f\x08\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02.\x08\x00\x08\x00\x00\x00| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x124\0$| p/Microsoft Terminal Services/ o/Windows XP/ cpe:/o:microsoft:windows_xp/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x12\x34\0$| p/Microsoft Terminal Services/ o/Windows 2003/ cpe:/o:microsoft:windows_2003/a
match ms-wbt-server m|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$| p/Microsoft Terminal Service/ i/Used with Netmeeting, Remote Desktop, Remote Assistance/ o/Windows/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a
match ms-wbt-server m|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$|s p/Microsoft NetMeeting Remote Desktop Service/ o/Windows/ cpe:/a:microsoft:netmeeting/ cpe:/o:microsoft:windows/a



##############################NEXT PROBE##############################
Probe UDP SNMPv1public q|0\x82\0/\x02\x01\0\x04\x06public\xa0\x82\0\x20\x02\x04\x4c\x33\xa7\x56\x02\x01\0\x02\x01\0\x30\x82\0\x10\x30\x82\0\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x05\0\x05\0|
rarity 4
ports 161

match bittorrent-udp-tracker m|^\x03\0\0\0lic\xa0Connection ID missmatch\.\0| p/opentracker UDP tracker/ cpe:/a:dirk_engling:opentracker/
match snmp m|^0.*\x02\x01\0\x04\x06public\xa2.*\x06\x08\+\x06\x01\x02\x01\x01\x05\0\x04[^\0]([^\0]+)|s p/SNMPv1 server/ i/public/ h/$1/

match snmp m|^0.*\x02\x01\0\x04\x06public\xa2|s p/SNMPv1 server/ i/public/

match echo m|^0\x82\0/\x02\x01\0\x04\x06public\xa0\x82\0\x20\x02\x04\x4c\x33\xa7\x56\x02\x01\0\x02\x01\0\x30\x82\0\x10\x30\x82\0\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x05\0\x05\0$|

##############################NEXT PROBE##############################
Probe UDP SNMPv3GetRequest q|\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\0\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\0\x02\x01\0\x02\x01\0\x04\0\x04\0\x04\0\x30\x12\x04\0\x04\0\xa0\x0c\x02\x02\x37\xf0\x02\x01\0\x02\x01\0\x30\0|
rarity 4
ports 161


match echo m|^\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\0\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\0\x02\x01\0\x02\x01\0\x04\0\x04\0\x04\0\x30\x12\x04\0\x04\0\xa0\x0c\x02\x02\x37\xf0\x02\x01\0\x02\x01\0\x30\0$|
# H.225 bandwidthReject
match H.323-gatekeeper-discovery m|^8\x02\x01\x10\0$| p/GNU Gatekeeper discovery/ cpe:/a:gnugk:gnu_gatekeeper/

# Enterprise numbers as used in SNMP engine IDs are here:
# http://www.iana.org/assignments/enterprise-numbers

# Reserved - SNMP Engine ID 0 \x00\x00
# Netgear GS748TS V5.0.0.23
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x00\x00|s

# Cisco - SNMP Engine ID 9 (CiscoSystems) = \x00\x09
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x00\x09|s p/Cisco SNMP service/

# Cisco - SNMP Engine ID 99 (SNMP Research) = \x00\x63
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x00\x63|s p/Cisco SNMP service/

# Xerox - SNMP Engine ID 253 (Xerox) = \x00\xfd
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x00\xfd|s p/Xerox SNMP service/

# Scientific Atlanta - SNMP Engine ID 1429 = \x05\x95
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x05\x95|s p/Scientific Atlanta SNMP service/

# Brocade - SNMP Engine ID 1588 (Brocade Communications Systems, Inc.) = \x06\x34
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x06\x34|s p/Brocade SNMP service/

# QLogic - SNMP Engine ID 1663 (Ancor Communications) = \x06\x7f
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x06\x7f|s p/QLogic SNMP service/

# IBM - SNMP Engine ID 1104 (First Virtual Holdins Incorporated) = \x04\x50
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x04\x50|s p/IBM SNMP service/

# Huawei - SNMP Engine ID 2011 (HUAWEI Technology Co.,Ltd) = \x07\xdb
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x07\xdb|s p/Huawei SNMP service/

# Lexmark - SNMP Engine ID 2021 (Engine Enterprise ID: U.C. Davis, ECE Dept. Tom) = \x07\xe5
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x07\xe5|s p/Lexmark SNMP service/

# Thomson Inc. - SNMP Engine ID 2863 (Thomson Inc.) = \x0b\x2f
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x0b\x2f|s p/Thomson SNMP service/

# Blue Coat - SNMP Engine ID 3417 (CacheFlow Inc.) = \x0d\x59
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x0d\x59|s p/Blue Coat SNMP service/

# Canon - SNMP Engine ID 4976 (Agent++) = \x13\x70
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x13\x70|s p/Canon SNMP service/

# net-snmp (net-snmp.org) - SNMP Engine ID 8072 (net-snmp) = \x1f\x88
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x1f\x88|s p/net-snmp/ cpe:/a:net-snmp:net-snmp/

# Fortigate-310B v4.0,build0324,110520 (MR2 Patch 7)
# Fortinet, Inc. - SNMP Engine ID 12356 = \x30\x44
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\x80\0\x30\x44|s p/Fortinet SNMP service/ d/firewall/

# Aruba Networks - SNMP Engine ID 14823 = \x39\xe7
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x39\xe7|s p/Aruba Networks SNMP service/

# OpenBSD Project - SNMP Engine ID 30155 = \x75\xcb
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\0\x75\xcb|s p/OpenBSD SNMP service/

# Wireshark says <MISSING> for the SNMP Engine ID.
match snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04.{5,6}\x01\0\x02\x03|s p/MikroTik router SNMP service/ d/router/

# Tandberg Video Conferencing equipment
match snmp m|^0\x82\0\x37\x02\x01\0\x04\x06public\xa2\x82\0\x28\x02.{41,43}\nSoftW:\x20([^\0\n]+)\nMCU:\x20([^\0\n]+)\n|s p/$2/ i/$1/

# Zebra GX430T label printer
match snmp m|^0\x82\0\x37\x02\x01\0\x04\x06public\xa2\x82\0\x28.{20}\x2b\x06\x01\x02\x01\x01\x05\0\x04\nZBR_SPICE0|s p/Zebra GX430T label printer SNMP service/ d/printer/ cpe:/h:zebra:gx430t/

# P-660HW-D1 from Zyxel
match snmp m|^0\x82\0\x3a\x02\x01\0\x04\x06public\xa2\x82\0\x2b.{20}\x06\x08\x2b\x06\x01\x02\x01\x01\x05\0\x04\x0bcfr25657985|s p/ZyXEL Prestige 660HW ADSL router/ d/broadband router/ cpe:/h:zyxel:prestige_660hw/

#Generic SNMPv3 matchline
softmatch snmp m|^..\x02\x01\x030.\x02\x02Ji\x02.{3,4}\x04\x01.\x02\x01\x03\x04|s p/SNMPv3 server/



############ SOCKS PROBES ############

# These are some simple probes that query a SOCKS server as specified in the
# following RFCs/documents:
#
# SOCKS4.Protocol - SOCKS Protocol Version 4
# RFC 1928 - SOCKS Protocol Version 5
# RFC 1929 - Username/Password Authentication for SOCKS V5
# RFC 1961 - GSS-API Authentication Method for SOCKS Version 5


# The following probe is designed to check the status of a SOCKS5 implementation.
#
# It attempts to create a TCP connection to google.com:80 assuming the SOCKS server
# allows unauthenticated connections. The probe also tells the SOCKS server
# that we support all major types of authentication so we can determine which
# authentication method the server requires.
#
# We don't try to establish TCP port bindings on the SOCKS server and we don't
# try UDP connections though these could easily be added to new probes.

Probe TCP Socks5 q|\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n|
rarity 8
ports 199,1080,1090,1095,1100,1105,1109,5000,6588,6660-6669,7777,8000,8008,8010,8080,8088,8888,9481,10801,10808,7890,20000,20202,20201

match caldav m|^HTTP/1\.1 503 Service Unavailable\r\nServer: DavMail Gateway ([\w._-]+)\r\nDAV: 1, calendar-access, calendar-schedule, calendarserver-private-events, addressbook\r\n(?:[^\r\n]+\r\n)*?Content-Length: 83\r\n\r\nInvalid header: google\.com\0PGET / HTTP/1\.0, HTTPS connection to an HTTP listener \? |s p/DavMail CalDAV http gateway/ v/$1/ d/proxy server/

# http://freenetproject.org/fcp.html
match fcp m|^ProtocolError\nFatal=true\nCodeDescription=ClientHello must be first message\nCode=1\nEndMessage\n$| p/Freenet Client Protocol 2.0/
match http m|^HTTP\/[0-9\.]+\s+[0-9]{3}\b.*$| p/HTTP/

match http m|^HTTP/1\.1 400 ERROR\r\nConnection: keep-alive\r\nContent-Length: 17\r\nContent-Type: text/html\r\n\r\n\r\ninvalid requestHTTP/1\.1 400 ERROR\r\nConnection: keep-alive\r\nContent-Length: 17\r\nContent-Type: text/html\r\n\r\n\r\ninvalid request| p/uTorrent http admin/ v/3.0/ cpe:/a:utorrent:utorrent:3.0/
match http m|^HTTP/1\.0 500 Unexpected new line: \x05\x04\0\x01\x02\x3f\x05\x01\0\x03\[CRLF\]\.\r\nContent-Type: text/html\r\nContent-Length: 763\r\nConnection: Close\r\n\r\n<html>\r\n    <head>\r\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\r\n        <title>Unexpected new line: \x05\x04\0\x01\x02\?\x05\x01\0\x03\[CRLF\]\.</title>\r\n    </head>\r\n    <body>\r\n        <h1>500 - Unexpected new line: \x05\x04\0\x01\x02\?\x05\x01\0\x03\[CRLF\]\.</h1>\r\n        <pre>System\.InvalidOperationException: Unexpected new line: \x05\x04\0\x01\x02\?\x05\x01\0\x03\[CRLF\]\.\n  at fp\.bb \(Char A_0\) \[0x00000\] in <filename unknown>:0 \n  at ha\.d \(\) \[0x00000\] in <filename unknown>:0 \n  at ha\.b \(System\.Byte\[\] A_0, Int32 A_1, Int32 A_2\) \[0x00000\] in <filename unknown>:0 \n| p/McMyAdmin Minecraft game admin console/ v/2.2.14/
match http m|^HTTP/1\.0 500 Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.\r\nContent-Type: text/html\r\nContent-Length: 769\r\nConnection: Close\r\n\r\n<html>\r\n    <head>\r\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\r\n        <title>Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.</title>\r\n    </head>\r\n    <body>\r\n        <h1>500 - Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.</h1>\r\n        <pre>System\.InvalidOperationException: Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.\n  at fp\.ba \(Char A_0\) \[0x00000\] in <filename unknown>:0 \n| p/McMyAdmin Minecraft game admin console/ v/2.2.14/
match http m|^HTTP/1\.0 500 Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.\r\nContent-Type: text/html\r\nContent-Length: 769\r\nConnection: Close\r\n\r\n<html>\r\n    <head>\r\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\r\n        <title>Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.</title>\r\n    </head>\r\n    <body>\r\n        <h1>500 - Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.</h1>\r\n        <pre>System\.InvalidOperationException: Unexpected new line: \x05\x04\0\x01\x02\xef\xbf\xbd\x05\x01\0\x03\[CRLF\]\.\n  at f8\.be \(Char A_0\) \[0x00000\] in <filename unknown>:0 \n| p/McMyAdmin Minecraft game admin console/
match http m|^HTTP/1\.1 400 Page not found\r\nServer: IPCamera-Web\r\nDate: .* \d\d\d\d\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><head><title>Document Error: Page not found</title></head>\r\n\t\t<body><h2>Access Error: Page not found</h2>\r\n\t\t<p>Bad request type</p></body></html>\r\n\r\n| p/Tenvis IP camera admin httpd/ d/webcam/
match http m|^\x05\x04\0\x01\x02\x80\x05\x01\0\x03\ngoogle\.com\0PGET / HTTP/1\.0\r\n\r\n\0HTTP/1\.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n| p/DeviceWISE Enterprise M2M httpd/ cpe:/a:telit:devicewise_m2m/

match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2\.0//EN\">\n<HTML><HEAD><TITLE>Error</TITLE></HEAD>\n<BODY><h2>400 Can not find method and URI in request</h2>\r\nWhen trying to load <a href=\"smartcache://url-parse-error\">smartcache://url-parse-error</a>\.\n<hr noshade size=1>\r\nGenerated by smart\.cache \(<a href=\"http://scache\.sourceforge\.net/\">Smart Cache ([\w._-]+)</a>\)\r\n</BODY></HTML>\r\n$| p/Smart Cache http-proxy/ v/$1/
match http-proxy m|^HTTP/.\.. 407 | p/http-proxy/ 

match socks5 m|^\x05\0\x05\0\0\x01.{6}HTTP|s i/No authentication required; connection ok/
match socks5 m|^\x05\0\x05\x01| i/No authentication; general failure/
match socks5 m|^\x05\0\x05\x02| i/No authentication; connection not allowed by ruleset/
match socks5 m|^\x05\0\x05\x03| i/No authentication; network unreachable/
match socks5 m|^\x05\0\x05\x04| i/No authentication; host unreachable/
match socks5 m|^\x05\0\x05\x05| i/No authentication; connection refused by destination host/
match socks5 m|^\x05\0\x05\x06| i/No authentication; TTL expired/
match socks5 m|^\x05\0\x05\x07| i|No authentication; command not supported/protocol error|
match socks5 m|^\x05\0\x05\x08| i/No authentication; address type not supported/

match socks5 m|^\x05\x01| i/GSSAPI authentication required/
match socks5 m|^\x05\x02| i|Username/password authentication required|

match socks5 m|^\x05\xFF$| i/No acceptable authentication method/

# When server doesn't buffer our probe properly. Seen on XMPP socks servers like Apple iChat, PyMSN, jabberd
match socks5 m|^\x05\0$| i/No authentication; connection failed/

softmatch socks5 m|^\x05|

# The following probe is designed to check the status of a SOCKS4 implementation.
#
# It attempts to create a TCP connection to 127.0.0.1:22. We supply a username root
# in the user id string field. We don't try to establish TCP port bindings on
# the SOCKS server though this could easily be added to a new probe.

Probe TCP Socks4 q|\x04\x01\x00\x16\x7f\x00\x00\x01root\x00|
rarity 8
ports 199,1080,1090,1095,1100,1105,1109,3128,6588,6660-6669,8000,8008,8080,8088

match socks4 m|^\0\x5a| i/Connection ok/
match socks4 m|^\0\x5b| i/Connection rejected or failed; connections possibly ok/
match socks4 m|^\0\x5c| i/Connection failed; ident required/
match socks4 m|^\0\x5d| i/Connection failed; username required/

match shell m|^\0Access is denied\n$| p/Windows Services for Unix rsh/ o/Windows/ cpe:/a:microsoft:windows_services_for_unix/ cpe:/o:microsoft:windows/a


##############################NEXT PROBE##############################
Probe TCP ms-sql-s q|\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00|
rarity 7
ports 1433,1434

match iscsi m|^\?\x80\x04\0\0\0\x000\0\0\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x12\x01\x004\0\0\0\0\0\0\x15\0\x06\x01\0\x1b\0\x01\x02\0\x1c\0\x0c\x03\0\(\0\x04\xff\x08\0\x01U\0\0\0MSSQLServer\0$| p/iSCSI Target/ d/phone/ o/iOS/ cpe:/o:apple:iphone_os/

# Specific minor version lines. Check bytes 30–33:
# \x0a \x32 \x06\x40 → 10.50.1600
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x00\xc2| p/Microsoft SQL Server 2000/ v/8.00.194; RTM/ o/Windows/ cpe:/a:microsoft:sql_server:2000:gold/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x01\x37| p/Microsoft SQL Server 2000/ v/8.00.311; RTMa/ o/Windows/ cpe:/a:microsoft:sql_server:2000/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x01\x7e| p/Microsoft SQL Server 2000/ v/8.00.384; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x01\x80| p/Microsoft SQL Server 2000/ v/8.00.384; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x02\x14| p/Microsoft SQL Server 2000/ v/8.00.532; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x02\x16| p/Microsoft SQL Server 2000/ v/8.00.534; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x02\xf8| p/Microsoft SQL Server 2000/ v/8.00.760; SP3/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x02\xfe| p/Microsoft SQL Server 2000/ v/8.00.766; SP3a/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp3a/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x03\x32| p/Microsoft SQL Server 2000/ v/8.00.818; SP3+ MS03-031/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x07\xf7| p/Microsoft SQL Server 2000/ v/8.00.2039; SP4/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp4/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x08\x02| p/Microsoft SQL Server 2000/ v/8.00.2050; SP4+ MS08-040/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp4/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x08\x00\x08\x07| p/Microsoft SQL Server 2000/ v/8.00.2055; SP4+ MS09-004/ o/Windows/ cpe:/a:microsoft:sql_server:2000:sp4/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x05\x77| p/Microsoft SQL Server 2005/ v/9.00.1399; RTM/ o/Windows/ cpe:/a:microsoft:sql_server:2005:gold/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x05\x7e| p/Microsoft SQL Server 2005/ v/9.00.1406/ o/Windows/ cpe:/a:microsoft:sql_server:2005/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x07\xff| p/Microsoft SQL Server 2005/ v/9.00.2047; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x08\x7a| p/Microsoft SQL Server 2005/ v/9.00.2170; SP1+/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0b\xe2| p/Microsoft SQL Server 2005/ v/9.00.3042; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0b\xee| p/Microsoft SQL Server 2005/ v/9.00.3054; SP2+/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0b\xfc| p/Microsoft SQL Server 2005/ v/9.00.3068; SP2+ MS08-040/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0c\x01| p/Microsoft SQL Server 2005/ v/9.00.3073; SP2+ MS08-052/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0c\x05| p/Microsoft SQL Server 2005/ v/9.00.3077; SP2+ MS09-004/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0c\x08| p/Microsoft SQL Server 2005/ v/9.00.3080; SP2+ MS09-062/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0f\xc3| p/Microsoft SQL Server 2005/ v/9.00.4035; SP3/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x0f\xd5| p/Microsoft SQL Server 2005/ v/9.00.4053; SP3+ MS09-062/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x10\x73| p/Microsoft SQL Server 2005/ v/9.00.4211; SP3+/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x13\x88| p/Microsoft SQL Server 2005/ v/9.00.5000; SP4/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp4/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x13\xcd| p/Microsoft SQL Server 2005/ v/9.00.5069; SP4+ MS12-070/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp4/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00\x14\xcc| p/Microsoft SQL Server 2005/ v/9.00.5324; SP4+ MS12-070 cumulative/ o/Windows/ cpe:/a:microsoft:sql_server:2005:sp4/ cpe:/o:microsoft:windows/
# Generic match for SQL Server 2005
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x09\x00(..)|s p/Microsoft SQL Server 2005/ v/9.00.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2005/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x04\x33| p/Microsoft SQL Server 2008/ v/10.00.1075; CTP/ o/Windows/ cpe:/a:microsoft:sql_server:2008/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x06\x40| p/Microsoft SQL Server 2008/ v/10.00.1600; RTM/ o/Windows/ cpe:/a:microsoft:sql_server:2008:gold/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x06\xfb| p/Microsoft SQL Server 2008/ v/10.00.1787; Cumulative Update 3/ o/Windows/ cpe:/a:microsoft:sql_server:2008/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x09\xe3| p/Microsoft SQL Server 2008/ v/10.00.2531; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x0a\xba| p/Microsoft SQL Server 2008/ v/10.00.2746; SP1+ Cumulative Update 5/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x0f\xa0| p/Microsoft SQL Server 2008/ v/10.00.4000; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x0f\xe0| p/Microsoft SQL Server 2008/ v/10.00.4064; SP2+ MS11-049/ o/Windows/ cpe:/a:microsoft:sql_server:2008/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x15\x7c| p/Microsoft SQL Server 2008/ v/10.00.5500; SP3/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x15\x88| p/Microsoft SQL Server 2008/ v/10.00.5512; SP3+ MS12-070/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x15\xa2| p/Microsoft SQL Server 2008/ v/10.00.5538; SP3+ MS15-058/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp3/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x17\x70| p/Microsoft SQL Server 2008/ v/10.00.6000; SP4/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp4/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00\x18\x61| p/Microsoft SQL Server 2008/ v/10.00.6241; SP4+ MS15-058/ o/Windows/ cpe:/a:microsoft:sql_server:2008:sp4/ cpe:/o:microsoft:windows/
# Generic match for SQL Server 2008
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x00(..)|s p/Microsoft SQL Server 2008/ v/10.00.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2008/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x06\x40| p/Microsoft SQL Server 2008 R2/ v/10.50.1600; RTM/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:gold/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x06\x51| p/Microsoft SQL Server 2008 R2/ v/10.50.1617; RTM+ MS11-049/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x09\xc4| p/Microsoft SQL Server 2008 R2/ v/10.50.2500; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x09\xf6| p/Microsoft SQL Server 2008 R2/ v/10.50.2550; SP1+ MS12-070/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x0f\xa0| p/Microsoft SQL Server 2008 R2/ v/10.50.4000; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x10\xb4| p/Microsoft SQL Server 2008 R2/ v/10.50.4276; SP2+ Cumulative Update 5/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x17\x70| p/Microsoft SQL Server 2008 R2/ v/10.50.6000; SP3/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2:sp3/ cpe:/o:microsoft:windows/
# Generic match for SQL Server 2008 R2
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32(..)|s p/Microsoft SQL Server 2008 R2/ v/10.50.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2008_r2/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x08\x34| p/Microsoft SQL Server 2012/ v/11.00.2100; RTM/ o/Windows/ cpe:/a:microsoft:sql_server:2012:gold/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x0b\xb8| p/Microsoft SQL Server 2012/ v/11.00.3000; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2012:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x0c\x38| p/Microsoft SQL Server 2012/ v/11.00.3128; SP1+/ o/Windows/ cpe:/a:microsoft:sql_server:2012:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x13\xc2| p/Microsoft SQL Server 2012/ v/11.00.5058; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2012:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x17\x84| p/Microsoft SQL Server 2012/ v/11.00.6020; SP3/ o/Windows/ cpe:/a:microsoft:sql_server:2012:sp3/ cpe:/o:microsoft:windows/
# Generic match for SQL Server 2012
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00(..)| p/Microsoft SQL Server 2012/ v/11.00.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2012/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x07\xd0| p/Microsoft SQL Server 2014/ v/12.00.2000/ o/Windows/ cpe:/a:microsoft:sql_server:2014/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x10\x04| p/Microsoft SQL Server 2014/ v/12.00.4100; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2014:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x10\x75| p/Microsoft SQL Server 2014/ v/12.00.4213; SP1+ MS15-058/ o/Windows/ cpe:/a:microsoft:sql_server:2014:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x13\x88| p/Microsoft SQL Server 2014/ v/12.00.5000; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2014:sp2/ cpe:/o:microsoft:windows/
# Generic match for SQL Server 2014
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00(..)|s p/Microsoft SQL Server 2014/ v/12.00.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2014/ cpe:/o:microsoft:windows/

# Generic match for SQL Server 2016
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0d\x00\x06\x41| p/Microsoft SQL Server 2016/ v/13.00.1601/ o/Windows/ cpe:/a:microsoft:sql_server:2016/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0d\x00\x0f\xa1| p/Microsoft SQL Server 2016/ v/13.00.4001; SP1/ o/Windows/ cpe:/a:microsoft:sql_server:2016:sp1/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0d\x00\x13\xa2| p/Microsoft SQL Server 2016/ v/13.00.5026; SP2/ o/Windows/ cpe:/a:microsoft:sql_server:2016:sp2/ cpe:/o:microsoft:windows/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0d\x00(..)| p/Microsoft SQL Server 2016/ v/13.00.$I(1,">")/ o/Windows/ cpe:/a:microsoft:sql_server:2016/ cpe:/o:microsoft:windows/

# No longer Windows-only
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0e\x00\x03\xe8|s p/Microsoft SQL Server 2017/ v/14.00.1000/ cpe:/a:microsoft:sql_server:2017/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0e\x00\x0c\xb9|s p/Microsoft SQL Server 2017/ v/14.00.3257; CU18/ cpe:/a:microsoft:sql_server:2017:cu18/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0e\x00(..)|s p/Microsoft SQL Server 2017/ v/14.00.$I(1,">")/ cpe:/a:microsoft:sql_server:2017/
match ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0f\x00(..)|s p/Microsoft SQL Server 2019/ v/15.00.$I(1,">")/ cpe:/a:microsoft:sql_server:2019/


softmatch ms-sql-s m|^\x04\x01\x00\x25\x00\x00\x01| p/Microsoft SQL Server/ o/Windows/ cpe:/a:microsoft:sql_server/ cpe:/o:microsoft:windows/

match ms-sql-s m|^\x04\x01\x00\x2b\x00\x00\x00\x00\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x00\x04\x00\x22\x00\x01\xff\x08\x00\x02\x10\x00\x00\x02\x00\x00| p/Dionaea honeypot MS-SQL server/


##############################NEXT PROBE##############################
# ActiveMQ's STOMP (Streaming Text Orientated Messaging Protocol)
Probe TCP HELP4STOMP q|HELP\n\n\0|
rarity 8
ports 6163,61613
#### Match versions based on line numbers in error messages.
# git clone https://github.com/apache/activemq.git
# cd activemq/activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/
# git tag -l | while read tag; do git checkout $tag -- ProtocolConverter.java; echo $tag:$(grep -n "Unknown STOMP action" ProtocolConverter.java) >> lines.txt; done

match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:270\)|s p/Apache ActiveMQ/ v/5.6.0 - 5.7.0 or 5.15.5 - 5.15.9/ cpe:/a:apache:activemq:5/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:254\)|s p/Apache ActiveMQ/ v/5.8.0/ cpe:/a:apache:activemq:5.8.0/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:241\)|s p/Apache ActiveMQ/ v/5.9.0 - 5.9.1/ cpe:/a:apache:activemq:5.9/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:267\)|s p/Apache ActiveMQ/ v/5.10.0/ cpe:/a:apache:activemq:5.10.0/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:266\)|s p/Apache ActiveMQ/ v/5.10.1 - 5.11.1/ cpe:/a:apache:activemq:5/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:268\)|s p/Apache ActiveMQ/ v/5.11.2 - 5.11.4/ cpe:/a:apache:activemq:5.11/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:269\)|s p/Apache ActiveMQ/ v/5.12.0 - 5.15.4/ cpe:/a:apache:activemq:5/
match stomp m|^ERROR\ncontent-type:text/plain\nmessage:Unknown STOMP action: HELP\n\norg\.apache\.activemq\.transport\.stomp\.ProtocolException: Unknown STOMP action: HELP\r\n\tat org\.apache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(ProtocolConverter\.java:244\)|s p/Apache ActiveMQ/ v/5.15.10 - 5.15.11/ cpe:/a:apache:activemq:5.15/

# catch-all softmatch. Add submitted fingerprints above using the line number as above.
softmatch stomp m|^ERROR\n(?:[^\n]+\n)?message:Unknown STOMP action:.+ org\.apache\.activemq\.|s p/Apache ActiveMQ/ cpe:/a:apache:activemq/
match stomp m|^ERROR\nmessage:Illegal command\ncontent-type:text/plain\nversion:([\d.,]+)\ncontent-length:\d+\n\nYou must log in using CONNECT first\0\n| p/RabbitMQ/ i/versions: $1/ cpe:/a:pivotal_software:rabbitmq/

# The following line matches IPDS (IBM's Intelligent Printer Data Stream) on port 9600
# match ipds m|^%%\[ Error: syntaxerror; Offending Command:|s p/IPDS Service/ d/printer/

##############################NEXT PROBE##############################
# Sends string 'stats' and matches memcached and zookeeper
Probe TCP Memcache q|stats\r\n|
rarity 8
ports 2181,11211
match memcached m|^STAT pid \d+\r\nSTAT uptime (\d+)\r\nSTAT time \d+\r\nSTAT version ([.\d]+)\r\n|s p/Memcached/ v/$2/ i/uptime $1 seconds/ cpe:/a:memcached:memcached:$2/
match memcached m|^STAT pid \d+\r\nSTAT uptime (\d+)\r\nSTAT time \d+\r\nSTAT version ([.\d]+) \(?Ubuntu\)?\r\n|s p/Memcached/ v/$2/ i/uptime $1 seconds; Ubuntu/ o/Linux/ cpe:/a:memcached:memcached:$2/ cpe:/o:canonical:ubuntu_linux/ cpe:/o:linux:linux_kernel/a
match zookeeper m|^Zookeeper version: ([\w.-]+), built on ([\w./]+)| p/Zookeeper/ v/$1/ i/Built on $2/ cpe:/a:zookeeper:zookeeper:$1/

softmatch memcached m|^STAT pid \d+\r\n|


##############################NEXT PROBE##############################
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 2
ports 1,70,79,80-85,88,113,139,143,280,497,505,514,515,540,554,591,620,631,783,888,898,900,901,1026,1080,1042,1214,1220,1234,1314,1344,1503,1610,1611,1830,1900,2001,2002,2030,2064,2160,2306,2396,2525,2715,2869,3000,3002,3052,3128,3280,3372,3531,3689,3872,4000,4444,4567,4660,4711,5000,5427,5060,5222,5269,5280,5432,5800-5803,5900,5985,6103,6346,6544,6600,6699,6969,7002,7007,7070,7100,7402,7776,8000-8010,8080-8085,8088,8118,8181,8530,8880-8888,9000,9001,9030,9050,9080,9090,9999,10000,10001,10005,11371,13013,13666,13722,14534,15000,17988,18264,31337,40193,50000,55555
sslports 443,993,995,1311,1443,3443,4443,5061,5986,7443,8443,8531,9443,10443,14443,44443,60443


match http-proxy m=^HTTP/1\.[01] \d\d\d .*\r\n(?:Server|Proxy-agent): iPlanet-Web-Proxy-Server/([\d.]+)\r\n=s p/iPlanet web proxy/ v/$1/ cpe:/a:sun:iplanet_web_server:$1/
match http-proxy m|^<h1>\xd5\xca\xba\xc5\xc8\xcf\xd6\xa4\xca\xa7\xb0\xdc \.\.\.</h1>\r\n<h2>IP \xb5\xd8\xd6\xb7: [][\w:.]+<br>\r\nMAC \xb5\xd8\xd6\xb7: <br>\r\n\xb7\xfe\xce\xf1\xb6\xcb\xca\xb1\xbc\xe4: \d+-\d+-\d+ \d+:\d+:\d+<br>\r\n\xd1\xe9\xd6\xa4\xbd\xe1\xb9\xfb: Invalid user\.</h2>$| p/CC Proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Type: text/html\r\nPragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=us-ascii\r\n\r\n<html><body>Invalid request<P><HR><i>This message was created by Kerio Control Proxy</i></body></html> {665}| p/Kerio Control http proxy/ cpe:/a:kerio:control/
match http-proxy m|^HTTP/HTTP/0\.0 408 Timeout\r\nServer: tinyproxy/([\w._-]+)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n| p/tinyproxy http proxy/ v/$1/ cpe:/a:banu:tinyproxy:$1/
match http-proxy m|^HTTP/1\.0 408 Timeout\r\nServer: tinyproxy/([\w._-]+)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n| p/tinyproxy http proxy/ v/$1/ cpe:/a:banu:tinyproxy:$1/
match http-proxy m|^<HEAD><TITLE>Invalid HTTP Request</TITLE></HEAD>\n<BODY BGCOLOR=\"white\" FGCOLOR=\"black\"><H1>Invalid HTTP Request</H1><HR>\n<FONT FACE=\"Helvetica,Arial\"><B>\nDescription: Bad request syntax</B></FONT>\n<HR>\n<!-- default \"Invalid HTTP Request\" response \(400\) -->\n</BODY>\n {400}\0| p/unknown transparent proxy/
match http-proxy m|^HTTP/.\.. 407 |  p/http-proxy-auth/
match http-proxy m%^HTTP/1\.0 400 Bad Request\r\nContent-Type: text/html\r\nPragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=(?:utf-8|us-ascii)\r\n\r\n<html><body>Invalid request<P><HR><i>This message was created by WinRoute Proxy</i></body></html>% p/WinRoute http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n.*<html><body>\t\t<i><h2>Invalid request:</h2></i><p><pre>Bad request format\.\n</pre><b>\t\t</b><p>Please, check URL\.<p>\t\t<hr>\t\tGenerated by Oops\.\t\t</body>\t\t</html>$|s p/Oops! http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.0 503 Internal error\r\nServer: awarrenhttp/([\w._-]+)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html> <head> <title> Internal Error </title> </head> <body> <hr> <p> An internal server error occurred while processing your request\. Please contact administrator\.\n<BR> <BR> Reason: Could not relay request </p> </body> </html>$| p/awarrenhttp http proxy/ v/$1/ i/Cyberoam CR200 proxy server/ d/proxy server/
match http-proxy m|^<HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD>\n<BODY><H2>501 Not Implemented</H2>\nThe requested method '' is not implemented by this server\.\n<HR>\n<I>httpd/1\.00</I></BODY></HTML>\n$| p/thttpd/ i/Blue Coat PacketShaper 3500 firewall/ d/firewall/ cpe:/a:acme:thttpd/ cpe:/h:bluecoat:packetshaper_3500/
match http-proxy m|^HTTP/1\.[01] (?:[^\r\n]*\r\n(?!\r\n))*?Server: Mikrotik HttpProxy\r\n|s p/MikroTik http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Type: text/html\r\nPragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>[^<]+<P><HR><i>[^<]*Kerio Control[^<]*?</i></body></html> {100}| p/Kerio Control http proxy/ cpe:/a:kerio:control/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\n\r\n$| p/sslstrip/
match http-proxy m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache\r\n(?:[^\r\n]+\r\n)*?X-orenosp-filt:|s p/Orenosp reverse http proxy/
match http-proxy m|^HTTP/.\.. 407 |  p/http-proxy-auth/
match http-proxy m|^HTTP/1\.1 400 Bad Request \( The data is invalid\.  \)\r\nVia:| p/Microsoft ISA Server http proxy/ o/Windows/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( The Uniform Resource Locator \(URL\) does not use a recognized protocol\. Either the protocol is not supported or the request was not typed correctly\. Confirm that a valid protocol is in use \(for example, HTTP for a Web request\)\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( L'URL \(Uniform Resource Locator\) n'utilise pas de protocole reconnu\. Le protocole n'est pas pris en charge, ou la demande n'a pas \xc3\xa9t\xc3\xa9 saisie correctement\. V\xc3\xa9rifiez qu'un protocole valide est utilis\xc3\xa9, par exemple HTTP pour une demande Web\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/French/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::fr/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( La direcci\xc3\xb3n URL \(Uniform Resource Locator\) no utiliza un protocolo reconocido\. El protocolo no es compatible o la petici\xc3\xb3n no se escribi\xc3\xb3 correctamente\. Confirme que se utiliza un protocolo v\xc3\xa1lido \(por ejemplo, HTTP para una petici\xc3\xb3n de web\)\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/Spanish/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::es/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( O URL n\xc3\xa3o usa um protocolo reconhecido\. N\xc3\xa3o h\xc3\xa1 suporte para o protocolo ou a solicita\xc3\xa7\xc3\xa3o n\xc3\xa3o foi digitada corretamente\. Confirme se um protocolo v\xc3\xa1lido est\xc3\xa1 em uso \(por exemplo, HTTP para uma solicita\xc3\xa7\xc3\xa3o da Web\)\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/Portuguese/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::pt/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( Die URL \(Uniform Resource Locator\) verwendet ein unbekanntes Protokoll\. Entweder wird das Protokoll nicht unterst\xc3\xbctzt, oder die Anforderung wurde nicht richtig eingegeben\. Vergewissern Sie sich, dass ein g\xc3\xbcltiges Protokoll, wie z\.B\. HTTP f\xc3\xbcr eine Webanforderung, verwendet wird\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/German/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::de/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( L'Uniform Resource Locator \(URL\) non utilizza un protocollo conosciuto\. Il protocollo non \xc3\xa8 supportato oppure la richiesta non \xc3\xa8 stata digitata correttamente\. Confermare la validit\xc3\xa0 del protocollo in uso \(ad esempio, HTTP per una richiesta Web\)\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/Italian/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::it/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( URL-\xd0\xb0\xd0\xb4\xd1\x80\xd0\xb5\xd1\x81 \xd0\xbd\xd0\xb5 \xd0\xb8\xd1\x81\xd0\xbf\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd1\x83\xd0\xb5\xd1\x82 \xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd0\xbc\xd1\x8b\xd0\xb9 \xd0\xbf\xd1\x80\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba\xd0\xbe\xd0\xbb\. \xd0\x9f\xd1\x80\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba\xd0\xbe\xd0\xbb \xd0\xbd\xd0\xb5 \xd0\xbf\xd0\xbe\xd0\xb4\xd0\xb4\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb8\xd0\xb2\xd0\xb0\xd0\xb5\xd1\x82\xd1\x81\xd1\x8f, \xd0\xbb\xd0\xb8\xd0\xb1\xd0\xbe \xd0\xb7\xd0\xb0\xd0\xbf\xd1\x80\xd0\xbe\xd1\x81 \xd0\xb2\xd0\xb2\xd0\xb5\xd0\xb4\xd0\xb5\xd0\xbd \xd0\xbd\xd0\xb5\xd0\xbf\xd1\x80\xd0\xb0\xd0\xb2\xd0\xb8\xd0\xbb\xd1\x8c\xd0\xbd\xd0\xbe\. \xd0\xa3\xd0\xb1\xd0\xb5\xd0\xb4\xd0\xb8\xd1\x82\xd0\xb5\xd1\x81\xd1\x8c, \xd1\x87\xd1\x82\xd0\xbe \xd0\xb8\xd1\x81\xd0\xbf\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd1\x83\xd0\xb5\xd1\x82\xd1\x81\xd1\x8f \xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbf\xd1\x80\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba\xd0\xbe\xd0\xbb \(\xd0\xbd\xd0\xb0\xd0\xbf\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80 HTTP \xd0\xb4\xd0\xbb\xd1\x8f \xd0\xb2\xd0\xb5\xd0\xb1-\xd0\xb7\xd0\xb0\xd0\xbf\xd1\x80\xd0\xbe\xd1\x81\xd0\xbe\xd0\xb2\)\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/Russian/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::ru/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( \xe7\xbb\x9f\xe4\xb8\x80\xe8\xb5\x84\xe6\xba\x90\xe5\xae\x9a\xe4\xbd\x8d\xe5\x99\xa8\(URL\)\xe6\x9c\xaa\xe4\xbd\xbf\xe7\x94\xa8\xe5\x8f\xaf\xe4\xbb\xa5\xe8\xaf\x86\xe5\x88\xab\xe7\x9a\x84\xe5\x8d\x8f\xe8\xae\xae\xe3\x80\x82\xe5\x8d\x8f\xe8\xae\xae\xe4\xb8\x8d\xe5\x8f\x97\xe6\x94\xaf\xe6\x8c\x81\xe6\x88\x96\xe9\x94\xae\xe5\x85\xa5\xe7\x9a\x84\xe8\xaf\xb7\xe6\xb1\x82\xe4\xb8\x8d\xe6\xad\xa3\xe7\xa1\xae\xe3\x80\x82\xe8\xaf\xb7\xe7\xa1\xae\xe8\xae\xa4\xe6\x89\x80\xe4\xbd\xbf\xe7\x94\xa8\xe7\x9a\x84\xe5\x8d\x8f\xe8\xae\xae\xe6\x9c\x89\xe6\x95\x88\(\xe4\xbe\x8b\xe5\xa6\x82\xef\xbc\x8c\xe4\xb8\xba Web \xe8\xaf\xb7\xe6\xb1\x82\xe4\xbd\xbf\xe7\x94\xa8 HTTP\)\xe3\x80\x82  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server Web Proxy/ i/Chinese (Simplified)/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::zh/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( \xe7\xb5\xb1\xe4\xb8\x80\xe8\xb3\x87\xe6\xba\x90\xe5\xae\x9a\xe4\xbd\x8d\xe5\x99\xa8 \(URL\) \xe6\xb2\x92\xe6\x9c\x89\xe4\xbd\xbf\xe7\x94\xa8\xe5\xb7\xb2\xe8\xbe\xa8\xe8\xad\x98\xe7\x9a\x84\xe9\x80\x9a\xe8\xa8\x8a\xe5\x8d\x94\xe5\xae\x9a\xe3\x80\x82\xe5\xa6\x82\xe6\x9e\x9c\xe4\xb8\x8d\xe6\x98\xaf\xe4\xb8\x8d\xe6\x94\xaf\xe6\x8f\xb4\xe9\x80\x9a\xe8\xa8\x8a\xe5\x8d\x94\xe5\xae\x9a\xef\xbc\x8c\xe5\xb0\xb1\xe6\x98\xaf\xe9\x8d\xb5\xe5\x85\xa5\xe7\x9a\x84\xe8\xa6\x81\xe6\xb1\x82\xe4\xb8\x8d\xe6\xad\xa3\xe7\xa2\xba\xe3\x80\x82\xe8\xab\x8b\xe7\xa2\xba\xe8\xaa\x8d\xe4\xbd\xbf\xe7\x94\xa8\xe4\xb8\xad\xe7\x9a\x84\xe9\x80\x9a\xe8\xa8\x8a\xe5\x8d\x94\xe5\xae\x9a\xe6\x9c\x89\xe6\x95\x88 \(\xe4\xbe\x8b\xe5\xa6\x82 Web \xe8\xa6\x81\xe6\xb1\x82\xe7\x9a\x84 HTTP\)\xe3\x80\x82  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server Web Proxy/ i/Chinese (Traditional)/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::zh_tw/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( URL\(Uniform Resource Locator\)\xec\x97\x90\xec\x84\x9c \xec\x9d\xb8\xec\x8b\x9d\xeb\x90\x9c \xed\x94\x84\xeb\xa1\x9c\xed\x86\xa0\xec\xbd\x9c\xec\x9d\x84 \xec\x82\xac\xec\x9a\xa9\xed\x95\x98\xec\xa7\x80 \xec\x95\x8a\xec\x8a\xb5\xeb\x8b\x88\xeb\x8b\xa4\. \xec\xa7\x80\xec\x9b\x90\xeb\x90\x98\xec\xa7\x80 \xec\x95\x8a\xeb\x8a\x94 \xed\x94\x84\xeb\xa1\x9c\xed\x86\xa0\xec\xbd\x9c\xec\x9d\xb4\xea\xb1\xb0\xeb\x82\x98 \xec\x9e\x85\xeb\xa0\xa5\xed\x95\x9c \xec\x9a\x94\xec\xb2\xad\xec\x9d\xb4 \xec\x98\xac\xeb\xb0\x94\xeb\xa5\xb4\xec\xa7\x80 \xec\x95\x8a\xec\x8a\xb5\xeb\x8b\x88\xeb\x8b\xa4\. \xec\x98\xac\xeb\xb0\x94\xeb\xa5\xb8 \xed\x94\x84\xeb\xa1\x9c\xed\x86\xa0\xec\xbd\x9c\xec\x9d\x84 \xec\x82\xac\xec\x9a\xa9\xed\x95\x98\xea\xb3\xa0 \xec\x9e\x88\xeb\x8a\x94\xec\xa7\x80 \xed\x99\x95\xec\x9d\xb8\xed\x95\x98\xec\x8b\xad\xec\x8b\x9c\xec\x98\xa4\. \xec\x98\x88\xeb\xa5\xbc \xeb\x93\xa4\xec\x96\xb4 \xec\x9b\xb9 \xec\x9a\x94\xec\xb2\xad\xec\x9d\x98 \xea\xb2\xbd\xec\x9a\xb0\xec\x97\x90\xeb\x8a\x94 HTTP\xec\x9e\x85\xeb\x8b\x88\xeb\x8b\xa4\.  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server Web Proxy/ i/Korean/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::ko/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( Uniform Resource Locator \(URL\) \xe8\xaa\x8d\xe8\xad\x98\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xa6\xe3\x81\x84\xe3\x82\x8b\xe3\x83\x97\xe3\x83\xad\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xab\xe3\x82\x92\xe4\xbd\xbf\xe7\x94\xa8\xe3\x81\x97\xe3\x81\xa6\xe3\x81\x84\xe3\x81\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x80\x82\xe3\x83\x97\xe3\x83\xad\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xab\xe3\x81\x8c\xe3\x82\xb5\xe3\x83\x9d\xe3\x83\xbc\xe3\x83\x88\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xa6\xe3\x81\x84\xe3\x81\xaa\xe3\x81\x84\xe3\x81\x8b\xe3\x80\x81\xe8\xa6\x81\xe6\xb1\x82\xe3\x81\x8c\xe6\xad\xa3\xe3\x81\x97\xe3\x81\x8f\xe5\x85\xa5\xe5\x8a\x9b\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x81\xa7\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82\xe6\x9c\x89\xe5\x8a\xb9\xe3\x81\xaa\xe3\x83\x97\xe3\x83\xad\xe3\x83\x88\xe3\x82\xb3\xe3\x83\xab \(Web \xe8\xa6\x81\xe6\xb1\x82\xe3\x81\xab\xe3\x81\xaf HTTP \xe3\x81\xaa\xe3\x81\xa9\) \xe3\x81\x8c\xe4\xbd\xbf\xe7\x94\xa8\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xa6\xe3\x81\x84\xe3\x82\x8b\xe3\x81\x93\xe3\x81\xa8\xe3\x82\x92\xe7\xa2\xba\xe8\xaa\x8d\xe3\x81\x97\xe3\x81\xa6\xe3\x81\x8f\xe3\x81\xa0\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ i/Japanese/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server::::ja/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( L'URL \(Uniform Resource Locator\) n'utilise pas de protocole reconnu\. Soit le protocole n'est pas pris en charge, soit la demande n'a pas \xe9t\xe9 tap\xe9e correctement\.| p/Microsoft ISA Server Web Proxy/ i/French/ o/Windows/ cpe:/a:microsoft:isa_server::::fr/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Proxy Error \( [^\r\n]+  \)\r\nVia: 1\.1 ([\w.-]+)\r\n| p/Microsoft ISA Server http proxy/ o/Windows/ h/$1/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required \( The ISA Server requires authorization to fulfill the request\. Access to the Web Proxy service is denied\.  \)\r\n| p/Microsoft ISA Server Web Proxy/ i/Proxy auth required/ o/Windows/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required \( El servidor ISA requiere autorizaci\xc3\xb3n para completar la petici\xc3\xb3n\. Acceso denegado al servicio de proxy web\.  \)\r\n| p/Microsoft ISA Server Web Proxy/ i/Spanish; Proxy auth required/ o/Windows/ cpe:/a:microsoft:isa_server::::es/ cpe:/o:microsoft:windows/a
match http-proxy m|^IsException=TRUE\r\nExceptionMsg=| p/Microsoft ISA Server Web Proxy/ o/Windows/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 200 OK\r\n.*<title>Web Filter Block Override</title>\n.*div\.header { background: url\(https?://:\d{1,5}/XX/YY/ZZ/CI/MGPGHGPGPFGHCDPFGGOGFGEH\) 0 0 repeat-x; height: 82px; }\n|s p/FortiGate Web Filtering Service/
match http-proxy m|^HTTP/1\.1 401 Unauthorized\r\nConnection: closed\r\nContent-Length: \d+\r\nWWW-Authenticate: Basic realm=\"WebWasher configuration\"\r\n| p/WebWasher filtering proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n.*<html><head><title>WebWasher - Error 400: Bad Request</title>|s p/WebWasher filtering proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\n.*<title>Webwasher - Notification</title>\r\n|s p/WebWasher filtering proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Ung\xfcltige Anforderung\r\nConnection: Close\r\nContent-type: text/html\r\nPragma: no-cache\r\n\r\n<html><head><title>WebWasher - Fehler 400: Ung\xfcltige Anforderung</title>| p/WebWasher filtering proxy/ i/German/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 463\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n<html><head><title>File not found</title></head><!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\">\n<body text=\"#000000\" bgcolor=\"#99AABB\"| p/Middleman filtering web proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nServer: WWWOFFLE/(\d[-.\w]+)\r\n| p/WWWOFFLE caching webproxy/ v/$1/
match http-proxy m|^HTTP/1\.[01] 400 Host Not Found.*\r\n\r\n<html><head><title>The Proxomitron Reveals\.\.\.</title>|s p/Proxomitron universal web filter/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nDate: .*\r\n\r\n<html><body>.*<font color=\"#FF0000\">Proxy</font><font color=\"#0000FF\">\+</font> (\d[-.\w]+) \(Build #(\d+)\), Date: |s p/Fortech Proxy+ http admin/ v/$1 Build $2/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nDate: .*\r\n\r\n<html><body>.*</b> Registration key allows only ([\d]+) simultaneous users\..*>Proxy</font><font color=\"#0000FF\">\+</font> ([\d.]+) \(Build #(\d+)\),|s p/Fortech Proxy+ http admin/ v/$2 Build $3/ i/$1 concurrent users allowed/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nServer: Jana-Server/(\d[-.\w]+)\r\n| p/JanaServer http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>DansGuardian - | p/DansGuardian HTTP proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nServer: FreeProxy/(\d[-.\w]+)\r\n| p/FreeProxy/ v/$1/
match http-proxy m|HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: EZproxy\r\n|s p/EZproxy web proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n(?:[^\r\n]+\r\n)*?\r\n<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\">\r\n<html>\r\n<head>\r\n  <title>BFilter Error</title>|s p/Bfilter proxy/
match http-proxy m|^HTTP/1\.0 501 Not Implemented\r\n.*<STRONG>\nUnsupported Request Protocol\n</STRONG>\n</UL>\n<P>\nBFilter does not support all request methods for all access protocols\.\n|s p/Bfilter proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nServer: tinyproxy/(\d[-.\w]+)\r\n| p/tinyproxy/ v/$1/ cpe:/a:banu:tinyproxy:$1/
match http-proxy m|^HTTP/1\.0 400 Invalid header received from browser\r\n\r\n$| p|Junkbuster/Privoxy webproxy|
match http-proxy m|^HTTP/1\.0 400 Invalid header received from browser\n\n| p/Junkbuster webproxy/
match http-proxy m|^HTTP/1\.1 400 Invalid header received from client| p/Privoxy http proxy/ 
match http-proxy m|^HTTP/1\.0 400 Bad request received from browser\r\nConnection: close\r\n\r\nBad request\. Privoxy was unable to extract the destination\.\r\n| p/Privoxy http proxy/
match http-proxy m|^HTTP/1\.1 400 Bad request received from client\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBad request\. Privoxy was unable to extract the destination\.\r\n| p/Privoxy http proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: NetCache \(NetApp/(\d[-.\w]+)\)\r\n|s p/NetApp NetCache http proxy/ v/$1/ cpe:/a:netapp:netcache:$1/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nDate: .*\r\nContent-Length: \d+\r\nContent-Type: text/html\r\nServer: NetCache appliance \(NetApp/([-\w_.]+)\)\r\n| p/NetApp NetCache http proxy/ v/$1/ cpe:/a:netapp:netcache:$1/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: 1\.1 [-\w_.]+ \(NetCache NetApp/(\d[-.\w]+)\)\r\n\r\n<h1>Bad Request \(Invalid Hostname\)</h1>|s p/NetApp NetCache http proxy/ v/$1/ cpe:/a:netapp:netcache:$1/
match http-proxy m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: [sS]quid/([-.\w+]+)\r\n|s p/Squid http proxy/ v/$1/ cpe:/a:squid-cache:squid:$1/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: [sS]quid\r\n|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.1 504 Gateway Time-out\r\nConnection: close\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Length: 2976\r\nContent-Type: text/html\r\n\r\n<DIV class=Section1> \n\t\t<P class=MsoNormal| p/Blue Coat Security Appliance http proxy/ o/SGOS/ cpe:/o:bluecoat:sgos/a
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nServer: MS-MFC-HttpSvr/([\w._-]+)\r\n| p/Microsoft Foundation Class httpd/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Cache Detected Error\r\nDate: .*\r\nContent-Type: text/html\r\nVia: 1\.0 ([-.\w]+) \(NetCache NetApp/([-.\w]+)\)\r\n\r\n| p/NetApp NetCache http proxy/ v/$2/ h/$1/ cpe:/a:netapp:netcache:$2/
match http-proxy m|^HTTP/1\.0 400 Cache Detected Error\r\nContent-type: text/html\r\n\r\n.*Generated by squid/([\w._-]+)@([\w._-]+)\n|s p/Squid http proxy/ v/$1/ h/$2/ cpe:/a:squid-cache:squid:$1/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nMime-Version: 1\.0\r\n.*<!-- \n /\*\n Stylesheet for Squid Error pages\n|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Content-Length: \d+\r\n\r\n.*<title>BorderManager Information Alert</title>|s p/Novell BorderManager HTTP-Proxy/ cpe:/a:novell:bordermanager/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-type: text/html\r\n\r\n<html><head><title>InterScan Error</title></head>\r\n<body><h2>InterScan Error</h2>\r\nInterScan HTTP Version ([-\w_.]+) \$Date:| p/InterScan InterScan VirusWall/ v/$1/
match http-proxy m|^HTTP/1\.1 \d\d\d .*\r\nServer: IBM-PROXY-WTE-US/([\d.]+)\r\n| p/IBM-PROXY-WTE-US web proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: IBM-PROXY-FW/([\d.]+)\r\n|s p/IBM-PROXY-FW http proxy/ v/$1/
match http-proxy m|^<HTML><BODY bgColor=#FFFFFF link=#0000CC text=#000000 vLink=#CCCC88><TITLE>An error has occurred\.\.\.</TITLE><CENTER><TABLE width=600 border=0 cellpadding=2 cellspacing=1><TR bgcolor=#FFFFFF vAlign=top><TD width=\"90%\" colspan=2 bgcolor=#707888>| p/AnalogX web proxy/ i/misconfigured/ cpe:/a:analogx:proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nContent-type: text/html\r\nContent-length: \d+\r\nWWW-authenticate: Basic realm=\"\(Password Only\) NAV for MS Exchange\"\r\n\r\n| p/NAV for MS Exchange/
match http-proxy m|^HTTP/1\.0 200 \nServer: VisualPulse \(tm\) ([\w.]+)\n| p/VisualPulse http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 302 Moved\r\nDate: .*\r\nServer: DeleGate/([\d.]+)\r\n| p/DeleGate proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 302 Moved\r\nDate: .*\r\nServer: DeleGate| p/DeleGate proxy/
match http-proxy m|^HTTP/1\.0 200 OK\r\nProxy-agent: Netscape-Proxy/([\d.]+)\r\n| p/Netscape-proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 504 Gateway Timeout\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n<H4><font COLOR=\"#FF0000\">Error parsing http request : </font></H2><p><pre>GET / / HTTP/1\.0\r\n\r\n</pre>| p/WinProxy http proxy/ o/Windows/ cpe:/a:bluecoat:winproxy/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nDate: .*\r\nContent-Length: \d+\r\nContent-Type: text/html\r\nServer: NetCache appliance \(NetApp/([\d.]+)\)\r\n\r\n| p/NetApp NetCache http proxy/ v/$1/ d/proxy server/ cpe:/a:netapp:netcache:$1/
match http-proxy m|^HTTP/1\.0  500 \r\nProxy-agent: MultiCertify PROXY/([\d.]+)\r\n| p/MultiCertify http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 \d\d\d .*\r\nDate: .*\r\nServer: HTTP::Proxy/([\d.]+)\r\n| p/Perl HTTP::Proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: BASIC realm=\"DOMBUD\"\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n| p/CacheFlow http proxy/ o/CacheOS/ cpe:/o:bluecoat:cacheos/
match http-proxy m|^HTTP/1\.1 404 Not found\r\nConnection: close\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body>HTTP/1\.1 404 Not found</body></html>$| p/HTTHost TCP over HTTP tunneling proxy/
match http-proxy m|^HTTP/1\.0 401 Unauthorized\r\nServer: Telkonet Communications\r\n| p/Telkonet Communications http proxy/
match http-proxy m|^HTTP/1\.1 204 No Content\r\n(?:[^\r\n]+\r\n)*?X-Squid-Error: ERR_INVALID_|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.[01] 400 Bad Request\r\n(?:[^\r\n]+\r\n)*?X-Squid-Error: ERR_INVALID_|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.0 503 Service Unavailable\r\n(?:[^\r\n]+\r\n)*?X-Squid-Error: ERR_CONNECT_FAIL 111\r\n|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.1 504 Gateway Time-out\r\n(?:[^\r\n]+\r\n)*?X-Squid-Error: ERR_CONNECT_FAIL 111\r\n|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^HTTP/1\.0 403 Access Forbidden\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>407 Proxy Authentication Required</TITLE></HEAD><BODY><H1>Proxy Authentication Required</H1><H4>Unable to complete request<P>Access denied due to authentication failure\.</H4><HR></BODY></HTML>\n\n\0| p/CA eTrust SCM http proxy/ cpe:/a:ca:etrust_secure_content_manager/
match http-proxy m|^HTTP/1\.1 \d\d\d .*\r\nServer: FreeProxy/([\d.]+)\r\n| p/FreeProxy http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: \d+\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: Close\r\n\r\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><TITLE>La solution mat\xc3\xa9rielle-logicielle WebShield&reg;| p/WebShield http proxy/ i/French/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 403 Forbidden\r\nServer: Eplicator/([\d.]+)\r\n| p/Eplicator http proxy/ v/$1/
match http-proxy m|^AdsGone Blocked HTML Ad$| p/AdsGone http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^<font face=verdana size=1>AdsGone (\d+)  Blocked HTML Ad</font>$| p/AdsGone $1 http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nDate: .*\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n<html>\n<head>\n<title>Proxy\+ WWW Admin interface</title>\n\n| p/Fortech Proxy+ http admin/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Cache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html.*\r\nProxy-Connection: close\r\nConnection: close\r\nContent-Length: \d+\r\n\r\n<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD>.*\n<big>Access Denied \(policy_denied\)</big>\n|s p/BlueCoat SG-400 http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Cache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html.*\r\nProxy-Connection: close\r\nConnection: close\r\nContent-Length: \d+\r\n\r\n<HTML><HEAD>\n<TITLE>Request Error</TITLE>\n</HEAD>.*\n<big>Request Error \(invalid_request\)</big>\n|s p/BlueCoat http proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: BlueCoat-Security-Appliance\r\n|s p/BlueCoat http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.1 302 Found\r\nServer: BlueCoat-Security-Appliance\r\nConnection: close\r\nLocation: /proxyclient/\r\n\r\n$| p/BlueCoat ProxyClient http interface/ d/proxy server/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nProxy-agent: BlueCoat-WinProxy\r\n| p/BlueCoat WinProxy http proxy/ d/proxy server/ o/Windows/ cpe:/a:bluecoat:winproxy/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Sawmill/([-\w_.]+)\r\n|s p/BlueCoat Sawmill http proxy config/ v/$1/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nProxy-agent: BlueCoat-ProxyAV\r\n| p/BlueCoat ProxyAV appliance http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nPragma: no-cach\r\nContent-Type: text/html; charset=windows-1251\r\n\r\n| p/UserGate http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Simple, Secure Web Server ([\d.]+)\r\n|s p/Symantec firewall http proxy/ i/Simple, Secure Web Server $1/ d/firewall/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Content-Length: \d+\r\n.*<B>KEN! Proxy</B>|s p/AVM KEN! http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad request\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n<H4><font COLOR=\"#FF0000\">Error parsing http request : </font></H2><p><pre>GET / / HTTP/1\.0\r\n\r\n</pre>| p/Kerio WinRoute Pro http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 200 OK\r\n.*This request is not allowed\n\n\n by One1Stream Fastlane Acceleration Server\.,  Accelerating Server ([\d.]+)</font></p></body></html>|s p/One1Stream Fastlane accelerating http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 404 Proxy Error\r\nContent-type: text/html\r\nPragma: no-cache\r\nCache-control: no-cache\r\nContent-length: \d+\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2\.0//EN\">\r\n<html><head><title>Proxy Error</title></head>\r\n<body><h1>Proxy Error</h1>\r\nThe proxy server could not handle this request\.\r\n<p>\r\n<b>bad file or wrong URL</b>\r\n</body></html>\r\n| p/Software602 602LAN Suite http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nProxy-agent: Ositis-WinProxy\r\n| p/Ositis-WinProxy http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^<Html><Body><H1> Unauthorized \.\.\.</H1></Body></Html>$| p/CCProxy http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^<pre>\r\nIP Address: [\d.]+\r\nMAC Address: \r\nServer Time: .*\r\nAuth result: Invalid user\.\r\n</pre>| p/CCProxy http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 401 Unauthorized\r\nServer: CCProxy\r\nWWW-Authenticate: Basic realm=\"CCProxy Authorization\"\r\n| p/CCProxy http proxy/ i/unauthorized/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 407 Unauthorized\r\nServer: CCProxy\r\nProxy-Authenticate: Basic realm=\"CCProxy Authorization\"\r\n| p/CCProxy http proxy/ i/unauthorized/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: WebMarshal Proxy\r\n|s p/WebMarshal http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n.*<br>Protocol:http\n<br>Host: [N]ULL\n<br>Path:/\n<tr>|s p/Oops! http proxy/
match http-proxy m|^HTTP/1\.0 504 Gateway Timeout\. Or not in cache\r\n\r\n| p/Oops! http proxy/
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"oops\"\r\n| p/Oops! http proxy/ i/Authentication Required/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Polipo\r\n|s p/Polipo http proxy/
match http-proxy m|^HTTP/1\.1 503 ERROR\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<html>\n<head>\n<title>Error: Unable to resolve IP</title>| p/ffproxy http proxy/
match http-proxy m|^HTTP/1\.1 200 OK\r\ndate: .*\r\nconnection: close\r\n\r\n<html><body><pre><h1>Index of /</h1>\n<b>Name {53}Size {6}Last modified</b>\n\n| p/HTTP Replicator proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: BestHop ([\d.]+)\r\n|s p/BestHop CacheFly http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 407 Authentication failed\r\nConnection: close\r\nProxy-Connection: close\r\nProxy-Authenticate: Basic realm=\"HTTP proxy\"\r\n| p/Astaro Security http proxy/ cpe:/a:astaro:security_gateway_software/
match http-proxy m|^HTTP/1\.0 503 Service unavailable\r\n\r\n\r\n<html>\r\n<head>\r\n<title>Connect server failed</title>\r\n</head>\r\n<body >\r\n<h3>503 Can not connect server</h3>\r\nezProxy meets some difficulties to connect this WWW server\.| p/ezProxy http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 403 Forbidden\r\nDate: .*\r\nServer: Mystery WebServer\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2\.0//EN\">\n<HTML><HEAD>\n<TITLE>403 Forbidden</TITLE>\n</HEAD><BODY>\n<H1>Forbidden</H1>\nYou don't have permission to access /\non this server\.<P>\n<HR>\n<ADDRESS>Mystery WebServer/([\d.]+) Server at ([-\w_.]+) Port \d+</ADDRESS>\n| p/Espion Interceptor http proxy/ v/$1/ h/$2/
match http-proxy m|^HTTP/1\.1 400 Bad Request .*Server: Traffic inspector HTTP/FTP[/ ]Proxy server \(([\w._-]+)\)\r\n|s p/Traffic Inspector http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 200 OK\r\nCache-Control: no-store\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nX-Bypass-Cache: Application and Content Networking System Software ([\d.]+)\r\n| p/Cisco ACNS outbound proxying/ v/$1/ cpe:/a:cisco:application_and_content_networking_system_software:$1/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*ERROR: The requested URL could not be retrieved|s p/Squid http proxy/ cpe:/a:squid-cache:squid/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*El URL solicitado no se ha podido conseguir|s p/Squid http proxy/ i/Spanish/ cpe:/a:squid-cache:squid::::es/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*A URL solicitada n&atilde;o pode ser recuperada|s p/Squid http proxy/ i/Portuguese/ cpe:/a:squid-cache:squid::::pt/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*La URL richiesta non pu&ograve; essere recuperata</TITLE>|s p/Squid http proxy/ i/Italian/ cpe:/a:squid-cache:squid::::it/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*L'URL demand&eacute;e n'a pu &ecirc;tre charg&eacute;e|s p/Squid http proxy/ i/French/ cpe:/a:squid-cache:squid::::fr/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">.*FEHLER: Der angeforderte URL konnte nicht geholt werden|s p/Squid http proxy/ i/German/ cpe:/a:squid-cache:squid::::de/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: FSAV4IGW\r\n.*<html><head><title>F-Secure Internet Gatekeeper Welcome Page</title>|s p/F-Secure Internet Gatekeeper httpd/
match http-proxy m|^HTTP/1\.[01] \d\d\d .*\r\nServer: twproxy/([-\w_.]+)\r\n| p/ThunderWeb twproxy/ v/$1/
match http-proxy m=^HTTP/1\.0 302 Redirect\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nContent-Length: 0\r\nConnection: close\r\nLocation: http://([\w._-]+):\d+/(?:nohost|nonauth/nohost\.php)\r\n\r\n= p/Kerio WinRoute http proxy/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication Required.*\r\nServer: HandyCache\r\n| p/HandyCache http caching proxy/ i/Russian/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: CF/v([\d.]+)\r\n(?:[^\r\n]+\r\n)*?X-Cache: MISS from CacheFORCE\r\n|s p/CacheForce http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 302 Found\r\nSet-Cookie:.*<TITLE>Novell Proxy</TITLE></HEAD><BODY><b><p>HTTP request is being redirected to HTTPS\.</b></BODY></HTML>\r\n|s p/Novell iChain http proxy/ o/NetWare/ cpe:/a:novell:ichain/ cpe:/o:novell:netware/a
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nServer: micro_proxy\r\n.*<ADDRESS><A HREF=\"http://www\.acme\.com/software/micro_proxy/\">micro_proxy</A>|s p/acme.com micro_proxy http proxy/ cpe:/a:acme:micro_proxy/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\n.*<br><b>Access denied due to Proxy\+'s Security settings!</b>|s p/Fortech Proxy+ http admin/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 200 OK\r\nServer: URL Gateway ([-\w_.]+)\r\n| p/URL Gateway http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: SonicWALL SSL-VPN Web Server\.?\r\n|s p/SonicWALL SSL-VPN http proxy/
match http-proxy m|^HTTP/1\.0 504 Web Acceleration Client Error \(400\.3\) - Missing Host Field in Request Header\r\nContent-type: text/html\r\nContent-length: \d+\r\n\r\n| p/HughesNet Web Acceleration http proxy/
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=.*<h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource|s p/3Proxy http proxy/
match http-proxy m|^HTTP/1\.1 400 Malformed Request\r\nServer: WinGate ([\d.]+) \(Build (\d+)\)\r\n| p/WinGate httpd/ v/$1 build $2/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m=^HTTP/1\.1 403 (?:Request|Access) [Dd]enied\r\nDate: .*\r\nCache-control: no-store, no-cache\r\nContent-Type: text/html\r\nContent-Length: \d+\r\nServer: WinGate Engine\r\n\r\n= p/WinGate http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.0 \d\d\d.*server: CoralWebPrx/([-\w_.]+) \(See http://coralcdn\.org/\)\r\n|s p/Coral Content Distribution Network http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Type: text/html\r\n\r\nYou are trying to use a node of the CoDeeN CDN Network\.| p/CoDeeN Content Distribution Network http proxy/
match http-proxy m|^HTTP/1\.0 403 Request error by HAVP\r\n.*<title>Yoggie - Unknown Request</title>|s p/Yoggie httpd/ i/HAVP anti-virus web proxy/
match http-proxy m|^HTTP/1\.0 403 Request error by HAVP\r\n| p/HAVP anti-virus web proxy/
match http-proxy m|^HTTP/1\.1 407\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Type: text/plain\r\n\r\nAccess denyed| p/Small HTTP Server http proxy/
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication required\r\nDate: .*\r\nContent-Type: text/html\r\nProxy-Authenticate: Basic realm=\"Proxy\+ HTTP Proxy service\"\r\n| p/Proxy+ http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 503 Freenet is starting up\r\n| p/Freenet FProxy/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Cache-Control: max-age=0, must-revalidate, no-cache, no-store, post-check=0, pre-check=0\r\n.*<title>Freenet FProxy Homepage|s p/Freenet FProxy/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Content-Security-Policy: default-src 'self'; script-src 'none'; frame-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'\r\n(?:[^\r\n]+\r\n)*?Cache-Control: private, max-age=0, must-revalidate, no-cache, no-store, post-check=0, pre-check=0\r\n|s p/Freenet FProxy/
match http-proxy m=^HTTP/1\.1 200 OK\r\nConnection: close\r\n.*<title>Browse Freenet \(Node id\|([\w._-]+)\) - Freenet</title>=s p/Freenet FProxy/ i/node id $1/
match http-proxy m|^HTTP/1\.1 200 OK\r\nConnection: close\r\n.*<title>Freenet Node of Node id\x7c([\w._-]+) - Freenet</title>|s p/Freenet FProxy/ i/node id $1/
match http-proxy m|^HTTP/1\.1 200 OK\r\nConnection: close\r\n.*<title>Browse Freenet \(([\w._-]+)\) - Freenet</title>|s p/Freenet FProxy/ i/node id $1/
match http-proxy m|^HTTP/1\.1 200 OK\r\nConnection: close\r\n.*<title>Freenet - Freenet</title>|s p/Freenet FProxy/
match http-proxy m|^HTTP/1\.[01] (?:[^\r\n]*\r\n(?!\r\n))*?Server: Mikrotik HttpProxy\r\n|s p/MikroTik http proxy/
match http-proxy m|^HTTP/1\.0 500 Internal Server Error\r\nCache-control: no-cache\r\nContent-type: text/html\r\n\r\n<HTML><HEAD><TITLE>SpoonProxy V([\w._-]+) Error</TITLE>| p/Pi-Soft SpoonProxy http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: approx/([\w._~+-]+) Ocamlnet/([\w._-]+)\r\n|s p/Approx http proxy/ v/$1/ i/Ocamlnet $2/
match http-proxy m|^HTTP/1\.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"Anti-Spam SMTP Proxy \(ASSP\) Configuration\"\nContent-type: text/html\nServer: ASSP/([\w._-]+)\(?\)?\n| p/Anti-Spam SMTP Proxy http config/ v/$1/
match http-proxy m|^HTTP/1\.0 \d\d\d .*<b>Bad request format\.\n\t\t</b><p>Please, check URL\.<p>\t\t<hr>\t\tGenerated by <a href=\"http://www\.kingate\.net\"> kingate\(([\w._-]+)-win32\)</a>\.</body></html>\0\0|s p/kingate http proxy/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^\njava\.net\.UnknownHostException: /\r\n\tat java\.net\.PlainSocketImpl\.connect\(Unknown Source\)\r\n| p/Apache JMeter http proxy/
match http-proxy m|^\r\n\r\njava\.net\.UnknownHostException: /\n\tat java\.net\.AbstractPlainSocketImpl\.connect\(AbstractPlainSocketImpl\.java:158\)\n| p/Apache JMeter http proxy/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<H1>I2P ERROR: NON-HTTP PROTOCOL</H1>The request uses a bad protocol\. The I2P HTTP Proxy supports http:// requests ONLY\. Other protocols such as https:// and ftp:// are not allowed\.<BR>|s p/I2P http proxy/
match http-proxy m|^HTTP/1\.1 405 Bad Method\r\n.*<H1>I2P ERROR: METHOD NOT ALLOWED</H1>The request uses a bad protocol\. The Connect Proxy supports CONNECT requests ONLY\. Other methods such as GET are not allowed - Maybe you wanted the HTTP Proxy\?\.<BR>|s p/I2P https proxy/
match http-proxy m|^HTTP/1\.0 502 Bad Gateway\r\nProxy-Connection: close\r\nContent-type: text/html; charset=us-ascii\r\n\r\n<html><head><title>502 Bad Gateway</title></head>\r\n<body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed</h3></body></html>\r\n| p/3proxy http proxy/
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: basic realm=\"proxy\"\r\nProxy-Connection: close\r\n.*<h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3>|s p/3proxy http proxy/ i/authentication required/
match http-proxy m|^HTTP/1\.0 404 Object not found\r\n.*<title>MIMEsweeper for Web :: ACCESS DENIED</title>|s p/Clearswift MIMEsweeper for web http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.1 200 .*<title>[\n ]*Web Filter Block Override[\n ]*</title>.*/XX/YY/ZZ/|s p/Fortinet FortiGuard http proxy/ d/firewall/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nServer: ziproxy\r\n.*\(ziproxy/([\w._-]+)\)</ADDRESS>|s p/ziproxy http proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nServer: ziproxy\r\n| p/ziproxy http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n\r\n\0{872}$| p/Ncat http proxy/ v/0.2/ i/before Nmap 4.85BETA1/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n\r\n$| p/Ncat http proxy/ i/Nmap 4.85BETA1 or later/
match http-proxy m|^HTTP/1\.1 404 Not found\r\nConnection: close\r\n.*<title>Proxy error: 404 Not found\.</title>\n.*<hr>Generated .* by Polipo on <em>([\w_.-]+):\d+</em>\.\n|s p/Polipo/ h/$1/
match http-proxy m|^HTTP/1\.1 401 Server authentication required\r\nConnection: close\r\n.*<title>Proxy error: 401 Server authentication required\.</title>.*<hr>Generated .*? by Polipo on <em>([\w._-]+):\d+</em>\.|s p/Polipo/ h/$1/
match http-proxy m|^HTTP/1\.0 500 Direct HTTP requests not allowed\nContent-type: text/html\n\n<font face=\"Bitstream Vera Sans Mono,Andale Mono,Lucida Console\">\nThe proxy is unable to process your request\.\n<h1><font color=red><b>Direct HTTP requests not allowed\.</b></font></h1>\n$| p/ratproxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\ncontent-type: text/html\r\n\r\n<h1>400</h1>\n<p>koHttpInspector: Could not understand the query: '/'</p>\n<hr>\n<address>Komodo Http Inspector, Port \d+</address>\n$| p/Komodo HTTP Inspector proxy/
match http-proxy m|^HTTP/1\.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: \d+\r\nCache-Control: no-cache\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n<style type=\"text/css\">\nbody{ font-family: Tahoma, Arial, sans-serif, Helvetica, Verdana; font-size: 11px; color: #000000; background-color: #FFFFFF; margin: 2 }\n| p/SafeSquid http proxy/
match http-proxy m|^HTTP/1\.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: Basic realm=\"proxy1\"\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n$| p/SafeSquid http proxy/
match http-proxy m|^HTTP/1\.0 302 Found\r\nServer: Distributed-Net-Proxy/([\d.]+)\r\nLocation: http://www\.distributed\.net/\r\n\r\n$| p/distributed.net personal key proxy httpd/ v/$1/
match http-proxy m|^HTTP/1\.0 200 OK\r\nServer: LastFMProxy/([\w.]+)\r\n| p/LastFMProxy HTTP-to-last.fm proxy/ v/$1/ cpe:/a:last:last.fm/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\n.*<TITLE>\r\nFEHLER: Der Zugriff auf die angeforderte URL war nicht erfolgreich\r\n</TITLE>.*<B>KEN! DSL Proxy</B>|s p/AVM KEN! DSL http proxy/
match http-proxy m|^HTTP/1\.0 404 Not Found\r\n.*<title>HINWEIS: Der Zugriff auf die angeforderte URL war nicht erfolgreich</title>|s p/AVM FRITZ!Box Fon WAP http proxy/ d/WAP/
match http-proxy m|^HTTP/1\.0 404 Not Found\r\n.*<title>HINWEIS: Die Internetnutzung ist gesperrt\.</title>|s p/AVM FRITZ!Box Fon WLAN 7100-series http proxy/ d/WAP/
match http-proxy m|^HTTP/1\.0 407 Proxy access denied\r\nProxy-Authenticate: NTLM\r\nProxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n$| p/ScanSafe http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\n(?:[^\r\n]+\r\n)*?Server: BaseHTTP/([\d.]+) Python/([\w._-]+)\r\n.*<head>\n<title>Error response</title>\n</head>\n<body>\n<h1>Error response</h1>\n<p>Error code 400\.\n<p>Message: Bad Request\.\n<p>Error code explanation: 400 = Bad request syntax or unsupported method\.\n</body>\n$|s p/BaseHTTPServer/ v/$1/ i/GAppProxy Google App Engine proxy; Python $2/ cpe:/a:python:basehttpserver:$1/a cpe:/a:python:python:$2/
match http-proxy m|^HTTP/1\.1 501 Not Implemented\r\n.*<title>This site is blocked</title>.*<img border=\"0\" src=\"http://([\w._-]+)/images-ip/ipblocked\.jpg\" \nuseMap=#links2 border=0>.*<area title=\"\" shape=RECT alt=\"\" coords=\"494, 20, 580, 105\" href=\"http://www\.etisalat\.ae\">|s p/Etisalat censorship http proxy/ i/site blocked/ h/$1/
match http-proxy m|^HTTP/1\.1 403 Forbidden\r\n.*<title>This site is blocked</title>.*<img border=\"0\" src=\"http://([\w._-]+)/images-ip/siteblocked\.jpg\" useMap=#links border=0>.*<area title=\"\" shape=RECT alt=\"\" coords=\"154, 449, 254, 463\" href=\"http://www\.etisalat\.ae/proxy\">|s p/Etisalat censorship http proxy/ i/site blocked/ h/$1/
match http-proxy m|^HTTP/1\.0 404 GlimmerBlocked\r\n| p/GlimmerBlocker http proxy/
match http-proxy m|^HTTP/1\.1 400 Bad Request \(Malformed HTTP request\)\r\n.*<HTML><TITLE>Vital Security Proxy Error</TITLE>|s p/Finjan Vital Security http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nConnection: Close\r\n\r\n<HTML><HEAD>\n<TITLE>ERROR: The requested URL could not be retrieved</TITLE>\n</HEAD><BODY>\n<H2>The requested URL could not be retrieved</H2>\n<HR>\n<P>\nWhile trying to retrieve the URL:\n| p/Websense http proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: HTTP/1\.1 ([\w._-]+) \(Websense_Content_Gateway/([\w._-]+) \[c s f \]\)\r\n|s p/Websense Content Gateway http proxy/ v/$2/ h/$1/ cpe:/a:websense:websense_content_content_gateway:$2/
match http-proxy m|^HTTP/1\.0 504 Gateway Timeout\r\nContent-Length: 237\r\n.*<p>The proxy server did not receive a timely response\nfrom the upstream server\.</p>|s p/Fortinet FortiGate-110c http proxy/ d/firewall/
match http-proxy m|^HTTP/1\.0 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><head><title>Statistics Report for HAProxy</title>| p/HAProxy http proxy/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>200 OK</h1>\nHAProxy: service ready\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.5.0/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 400 Bad request\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 408 Request Time-out\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 500 Server Error\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>500 Server Error</h1>\nAn internal server error occured\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 502 Bad Gateway\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 503 Service Unavailable\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 504 Gateway Time-out\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time\.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1.0 401 Unauthorized\r\nCache-Control: no-cache\r\nConnection: close\r\nWWW-Authenticate: Basic realm=".*"\r\n\r\n<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n$| p/HAProxy http proxy/ v/before 1.3.1/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 400 Bad request\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 408 Request Time-out\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 500 Server Error\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Server Error</h1>\nAn internal server error occured\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 502 Bad Gateway\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 503 Service Unavailable\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 504 Gateway Time-out\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1.0 401 Unauthorized\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\nWWW-Authenticate: Basic realm=".*"\r\n\r\n<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n$| p/HAProxy http proxy/ v/1.3.1 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1.0 407 Unauthorized\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\nProxy-Authenticate: Basic realm=".*"\r\n\r\n<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n$| p/HAProxy http proxy/ v/1.4.0 - 1.5.10/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>200 OK</h1>\nService ready\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.5.0 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 405 Method Not Allowed\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource\n</body></html>\n$| p/HAProxy http proxy/ v/1.6.0 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 429 Too Many Requests\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.6.0 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 407 Unauthorized\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\nProxy-Authenticate: Basic realm=".*"\r\n\r\n<html><body><h1>407 Unauthorized</h1>\nYou need a valid user and password to access this content\.\n</body></html>\n$| p/HAProxy http proxy/ v/1.5.10 or later/ d/load balancer/ cpe:/a:haproxy:haproxy/
match http-proxy m|^HTTP/1\.0 400\r\nContent-Type: text/html\r\n\r\n<html><head><title>Error</title></head><body>\r\n<h2>ERROR: 400</h2>\r\n<br>\r\n</body></html>\r\n$| p/Citrix Application Firewall/ d/firewall/
match http-proxy m|^HTTP/1\.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 3366\r\nPragma: no-cache\r\n\r\n.*<style>\r\n\r\nh1, p, a, body {font-family: Arial;}\r\n\r\nh2\r\n{\r\n\ttext-align: center; \r\n\tfont: bold 20px Verdana, sans-serif; \r\n\tcolor: #00F; \r\n}|s p/Integard filtering http proxy management interface/ d/proxy server/
match http-proxy m|^HTTP/1\.0 502 Bad gateway\r\n\r\nBurp proxy error: invalid client request received: first line of request did not contain an absolute URL - try enabling invisible proxy support\r\n$| p/Burp Suite Pro http proxy/
match http-proxy m|^HTTP/1\.0 502 Bad gateway\r\n\r\nBurp proxy error: Invalid client request received: First line of request did not contain an absolute URL - try enabling invisible proxy support\r\n$| p/Burp Suite Pro http proxy/ v/1.5/
match http-proxy m|^HTTP/1\.1 401 Unauthorized\r\nServer: RabbIT proxy version ([\w._-]+)\r\nContent-type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nDate: .*\r\nWWW-Authenticate: Basic realm=\"([\w._-]+):\d+\"\r\n| p/RabbIT http proxy/ v/$1/ h/$2/
match http-proxy m|^HTTP/1\.1 403 Forbidden\r\nServer: Lusca/([\w._-]+)\r\n| p/Lusca http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 403 Access Denied\r\nConnection: close\r\n\r\n<html>The request you issued is not authorized for GoogleSharing\.\n| p/GoogleSharing http proxy/
match http-proxy m|^HTTP/1\.0 503\r\nServer: Charles\r\n| p/Charles http proxy/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: http/1\.[01] ([\w._-]+) \(ApacheTrafficServer[^)]*\)\r\nServer: ATS/([\w._-]+)\r\n|s p/Apache Traffic Server/ v/$2/ h/$1/ cpe:/a:apache:traffic_server:$2/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: http/1\.[01] ([\w._-]+) \(ApacheTrafficServer[^)]*\)\r\nServer: ATS\r\n|s p/Apache Traffic Server/ h/$1/ cpe:/a:apache:traffic_server/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: ATS/([\w._-]+)\r\n|s p/Apache Traffic Server/ v/$1/ cpe:/a:apache:traffic_server:$1/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: ATS\r\n|s p/Apache Traffic Server/ cpe:/a:apache:traffic_server/
match http-proxy m|^HTTP/1\.0 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: http/1\.1 ([\w._-]+) \([^\)]+ \[c[M ]s[S ]f \]\)\r\nServer: [^/]+/([\d.]+)\r\n|s p/Apache Traffic Server/ v/$2/ h/$1/ cpe:/a:apache:traffic_server:$2/
match http-proxy m|^HTTP/1\.0 200 OK\r\nACCEPT-RANGES: none\r\n\r\n<html><head><Title>SecTitan&#153; Reverse Proxy</title></head><body><center><h1>Error 107</h1>Invalid Request!<br><b>SecTitan&#153; Reverse Proxy ([\w._-]+)</b><br>Copyright &copy; \d+ Bestellen Software, LLC All rights reserved\.</center></body></html>| p/Bestellen SecTitan reverse http proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 \d\d\d .*\r\nServer: Varnish\r\n| p/Varnish/ cpe:/a:varnish-cache:varnish/
match http-proxy m|^HTTP/1\.0 503 Internal Error\r\nServer: awarrenhttp/([\w._-]+)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<HTML><HEAD>\n<TITLE>ERROR: The requested URL could not be retrieved</TITLE>\n</HEAD><BODY>\n<H1>ERROR</H1>\n<H2>The requested URL could not be retrieved</H2>| p/awarrenhttp http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 404 No service found\r\nDate: .*\r\nServer: ACE XML Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 30\r\n\r\nNo service matched the request| p/Cisco Application Control Engine XML gateway/ d/load balancer/ cpe:/a:cisco:application_control_engine_software/
match http-proxy m|^HTTP/1\.0 403 Request error by HTTP PROXY\r\nContent-Type: text/html\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n<html><head><meta http-equiv=\"Content-Language\" content=\"en-us\"><title>Cisco ([\w._-]+)</title>| p/Cisco $1 http proxy/ d/firewall/
match http-proxy m|^HTTP/1\.0 200 OK\r\n(?:[^\r\n]+\r\n)*?Server: PAW Server ([\w._-]+-android) \(Brazil/2\.0\)\r\n|s p/PAW http proxy/ v/$1/ d/phone/ o/Android/ cpe:/o:google:android/
match http-proxy m|^HTTP/1\.1 200 OK\r\nServer: NETLAB/([\w._-]+)\r\n| p/Cisco NETLab http proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html; charset=utf-8\r\nProxy-Connection: close\r\nConnection: close\r\n.*<TITLE>P\xc3\xa1gina de Error invalid_request</TITLE>|s p/Blue Coat ProxySG firewall/ i/Spanish/ d/firewall/ cpe:/h:bluecoat:proxysg::::es/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\nContent-Type: text/html; charset=UTF-8\r\nCache-control: no-cache\r\nConnection: close\r\nProxy-Connection: close\r\n.*<title>I2P Warning: Non-HTTP Protocol</title>|s p/I2P http proxy/
match http-proxy m|^HTTP/1\.0 301 Moved Permanently\r\nLocation: http:/index\.html\r\nWWW-Authenticate: Basic realm=\"([\w._-]+)\" \r\nServer: Repro Proxy Repro ([\w._-]+)/000000@SC-VPRABHU\r\n| p/Repro http proxy/ v/$2/ h/$1/
match http-proxy m|^HTTP/1\.1 200 OK\r\nDate: .*\r\nAllow: GET, HEAD\r\nServer: Oracle-Web-Cache/11g \(([\w._-]+)\)\r\n| p/Oracle Web Cache http proxy/ v/$1/ cpe:/a:oracle:application_server_web_cache:$1/
match http-proxy m|^HTTP/1\.1 200 I'm sorry, Dave\. I'm afraid I can't work without a host header\.\r.*\nServer: Haste\r\n|s p/Haste http proxy/ v/2.0/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nServer: smartcds/([\w.]+)\r\n| p/SmartCDS http proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 400 Bad request: request-line invalid\r\nContent-type: text/html; charset=\"utf-8\"\r\n\r\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1\.0 Strict//EN\" \"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n  <head>\r\n    <title>Request denied by WatchGuard HTTP Proxy</title>| p/WatchGuard http proxy/
match http-proxy m|^HTTP/1\.0 400 Bad request: request-line invalid\r\nContent-type: text/html; charset="iso-8859-1"\r\n\r\n<html>\r\n<body>\r\n<h3> Request denied by WatchGuard HTTP proxy\. </h3>| p/WatchGuard http proxy/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?X-Varnish: \d+\r.*\nVia: 1\.1 varnish\r\n|s p/Varnish http accelerator/ cpe:/a:varnish-cache:varnish/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Varnish\r.*\nX-Varnish: \d+\r\n|s p/Varnish http accelerator/ cpe:/a:varnish-cache:varnish/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Via: 1\.1 varnish-v(\d)\r\n|s p/Varnish http accelerator/ v/$1/ cpe:/a:varnish-cache:varnish:$1/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nDate: .*\r\nServer: Microdasys-SCIP\r\nContent-Type: text/html\r\nContent-Length: 240\r\nConnection: close\r\n\r\n<HTML>.*<ADDRESS><A HREF=\"http://www\.websense\.com/\">Websense Content Gateway Proxy v([\w._-]+)</A>| p/Websense Content Gateway http proxy/ v/$1/ i/Microdasys SCIP ssl proxy/ cpe:/a:websense:websense_content_content_gateway:$1/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nDate: .*\r\nServer: Microdasys-SCIP\r\n| p/Microdasys SCIP ssl proxy/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nServer: mitmproxy ([\w._-]+)\r\nContent-type: text/html\r\nContent-Length: \d+\r\n| p/mitmproxy/ v/$1/
match http-proxy m|^HTTP/1\.1 302 Found\r\nDate: .*\r\nServer: xxxx\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=31536000\r\nLocation: https:///webconsole/webpages/login\.jsp\r\n|
match http-proxy m|^HTTP/1\.1 302 Found\r\nDate: .*\r\nServer: xxxx\r\n(?:X-Frame-Options: SAMEORIGIN\r\n(?:Strict-Transport-Security: max-age=\d+\r\n)?)?Location: https?://[^\r\n]+?/webpages/(?:myaccount/)?login\.jsp\r\nCache-Control: max-age=2592000\r\nExpires: .*\r\n(?:Vary: Accept-Encoding\r\n)?Content-Length: \d+\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n| p/Cyberoam captive portal/
match http-proxy m=^HTTP/1\.1 200 OK\r\nConnection: close\r\nCache-control: no-cache\r\nPragma: no-cache\r\nCache-control: no-store\r\n(?:X-Frame-Options: DENY\r\n)?\r\n<html><head><title>Burp Suite (Professional|Free Edition)</title>= p/Burp Suite $1 http proxy/ cpe:/a:portswigger:burp_suite:::$1/
match http-proxy m%^HTTP/1\.1 200 OK\r\nConnection: close\r\nCache-control: no-cache, no-store\r\nPragma: no-cache\r\nX-Frame-Options: DENY\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n\r\n<html><head><title>Burp Suite (Professional|Free Edition)% p/Burp Suite $1 http proxy/ cpe:/a:portswigger:burp_suite:::$1/
match http-proxy m|^HTTP/1\.0 400 Bad request received from client\r\nProxy-Agent: Seeks proxy ([\w._-]+)\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBad request\. Seeks proxy was unable to extract the destination\.\r\n| p/Seeks websearch proxy/ v/$1/
match http-proxy m|^HTTP/1\.1 500\r\nAlternate-Protocol: 443:quic\r\nVary: Accept-Encoding\r\nServer: Google Frontend\r\nCache-Control: private\r\nDate: Thu, 06 Feb 2014 14:10:57 GMT\r\nContent-Type: text/html\r\n\r\n\n    <html><head>\n    <meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n    <title>502 Urlfetch Error</title>| p/GoAgent http proxy/ i/Google App Engine/
match http-proxy m|^HTTP/1\.1 200 Document follows\r\nServer: IBM-PROXY-WTE/([\w._-]+)\r\n| p/IBM WebSphere Edge caching proxy/ v/$1/
match http-proxy m|^HTTP/1\.0 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Connection: close\r\nProxy-Authenticate: NTLM\r\nContent-Length: \d+\r\nContent-type: text/html\r\n\r\n<html><head><title>NTLM Authentication Failed</title></head><body><center><table border=0 cellpadding=5 width=65%><tr><td align=middle><!-- \.{525}--><table border=2 cellpadding=20 bgcolor=#C0C0C0><tr><td>NTLM Authentica| p/Smoothwall proxy/ i/NTLM authentication/
match http-proxy m|^HTTP/1\.1 400 Received invalid request from Client\r\nDate: .*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html; charset=\"UTF-8\"\r\nContent-Length: \d+\r\nAccept-Ranges: none\r\nProxy-Connection: close\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4\.01 Transitional//EN\" \"http://www\.w3\.org/TR/html4/loose\.dtd\">\n<html>\n  <head>\n    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n    <title>The requested URL could not be retrieved</title>| p|Sophos/Astaro UTM gateway| d/security-misc/ cpe:/a:astaro:security_gateway_software/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 84\r\n\r\n{\"fault\":{\"faultstring\":\"\\\"Missing Host header\\\"\",\"detail\":{\"code\":\"MISSING_HOST\"}}}| p/Apigee API proxy/
match http-proxy m|^HTTP/1\.0 400 badrequest\r\nVia: 1\.0 ([\w.-]+) \(McAfee Web Gateway ([\w._-]+)\)\r\nConnection: Close\r\n| p/McAfee Web Gateway/ v/$2/ i/Via $1/ cpe:/a:mcafee:web_gateway:$2/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Length: 113\r\nDate: .*\r\nExpires: 0\r\n\r\n<html>\n<head><title>Error 400: Bad Request</title></head>\n<body>\n<h1>Error 400: Bad Request</h1>\n</body>\n</html>\n| p/Mikrotik HotSpot http proxy/
match http-proxy m|^HTTP/1\.0 400 Host Required In Request\r\nDate: .*\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: text/html\r\nContent-Language: en\r\nContent-Length: \d+\r\n\r\n<HTML>\n<HEAD>\n<TITLE>Host Header Required</TITLE>\n</HEAD>\n\n<BODY BGCOLOR=\"white\" FGCOLOR=\"black\">\n<H1>Host Header Required</H1>\n<HR>\n\n<FONT FACE=\"Helvetica,Arial\">| p/Cyberoam UTM http proxy/
match http-proxy m|^HTTP/1\.1 504 Gateway Timeout\r\nContent-Length: 15\r\nContent-Type: text/plain;\r\n\r\nZAP Error: null| p/OWASP Zed Attack Proxy/
match http-proxy m|^HTTP/1\.1 502 Bad Gateway\r\nContent-Length: \d+\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nZAP Error \[java\.net\.UnknownHostException\]: null| p/OWASP Zed Attack Proxy/
match http-proxy m|^HTTP/1\.0 502\r\nContent-type: text/html\r\nContent-length: \d+\r\nproxy-Connection: close\r\n\r\n<html>\r\n<head>\r\n\t<title>Spybot - Connection refused</title>\r\n| p/Spybot Search & Destroy/ o/Windows/ cpe:/a:safer-networking:spybot_search_and_destroy/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required\r\nContent-Length: 36\r\nContent-Type: text/html; charset=UTF-8\r\naw-error-code: 1\r\n\r\nMissing \[Proxy-Authorization\] header| p/AirWatch Mobile Access Gateway/ d/proxy server/ cpe:/a:airwatch:mobile_access_gateway/
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required\r\naw-error-code: 1\r\n\r\n$| p/AirWatch Mobile Access Gateway/ d/proxy server/ cpe:/a:airwatch:mobile_access_gateway/
match http-proxy m|^HTTP/1\.0 404 Not Found\r\nServer: Traffic Manager ([\w._-]+)\r\nDate: .*\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-type: application/x-ns-proxy-autoconfig\r\n| p/Apache Traffic Server/ v/$1/ d/proxy server/ cpe:/a:apache:traffic_server:$1/
match http-proxy m|^HTTP/1\.1 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nPragma: no-cache\r\nContent-Length: \d+\r\n\r\n<html><head><title>Request Rejected</title></head><body>The requested URL was rejected\. Please consult with your administrator\.<br><br>Your support ID is: \d+</body></html>| p/F5 BIG-IP Application Security Module/ d/load balancer/
match http-proxy m|^HTTP/1\.0 \d\d\d .*\r\nMime-Version: 1\.0\r\nDate: .*\r\nVia: 1\.0 ([\w.-]+):\d+ \(Cisco-WSA/([\w._-]+)\)\r\n| p/Cisco Web Security Appliance/ i/Gateway Timeout/ o/AsyncOS $2/ h/$1/ cpe:/o:cisco:asyncos:$2/
match http-proxy m|^HTTP/1\.1 \d\d\d [^\r\n]+\r\nDate: [^\r\n]+\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: text/html; charset="UTF-8"\r\nContent-Length: \d+\r\nAccept-Ranges: none\r\nConnection: close\r\n\r\n.*href="http://passthrough\.fw-notify\.net/|s p/Sophos UTM http proxy/ d/security-misc/ cpe:/a:sophos:unified_threat_management/
match http-proxy m|^HTTP/1\.1 302 Found\r\nDate: .*\r\nServer: xxxx\r\nLocation: http:///httpclient\.html\r\nContent-Length: \d+\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n| p/Cyberoam captive portal/
match http-proxy m|^HTTP/1\.1 403 No Protocol\r\nX-Hola-Error: No Protocol\r\nDate: .*\r\nConnection: close\r\n\r\n$| p/Hola VPN http-proxy/ cpe:/a:hola:hola/
match http-proxy m|^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Traffic Inspector HTTP/FTP/Proxy server \(([\d.]+)\)\r\n|s p/Traffic Inspector http proxy/ v/$1/ o/Windows/ cpe:/a:smart-soft:traffic_inspector:$1/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 404 Not Found\r\nServer: Sucuri/Cloudproxy\r\nDate: .* GMT\r\nContent-Type: text/html\r\nContent-Length: \d+\r\nConnection: close\r\nETag: "[a-f\d-]+"\r\n\r\n<!DOCTYPE html>\n\n<html lang="en">\n\n| p/Sucuri CloudProxy/
match http-proxy m|^HTTP/1\.0 30[12] .*\r\nLocation: https?:///[^\r\n]*\r\nServer: LBaaS\r\n| p/OpenStack Neutron LBaaS load balancer/ cpe:/a:openstack:neutron-lbaas/
match http-proxy m|^HTTP/1\.1 200 OK\r\nDate: .*\r\nContent-Length: \d+\r\nEtag: "[a-f\d]{40}"\r\nContent-Type: text/html; charset=UTF-8\r\nServer: Protegrity Cloud Gateway ([\d.]+)\r\n\r\nProtegrity Cloud Gateway ([\w._-]+)<BR>| p/Protegrity Cloud Gateway/ v/$1/ h/$2/ cpe:/a:protegrity:cloud_gateway:$1/
match http-proxy m|^HTTP/1\.1 502 Bad Gateway\r\n(?:[^\r\n]+\r\n)*?\r\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2\.0//EN">\r\n<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body bgcolor="white">\r\n<h1>502 Bad Gateway</h1>\r\n<p>The proxy server received an invalid response from an upstream server\. Sorry for the inconvenience\.<br/>\r\nPlease report this message and include the following information to us\.<br/>\r\nThank you very much!</p>\r\n<table>\r\n<tr>\r\n<td>URL:</td>\r\n<td>[^<]*</td>\r\n</tr>\r\n<tr>\r\n<td>Server:</td>\r\n<td>([^<]+)</td>\r\n</tr>\r\n<tr>\r\n<td>Date:</td>\r\n<td>[^<]+</td>\r\n</tr>\r\n</table>\r\n<hr/>Powered by Tengine</body>\r\n</html>\r\n$|s p/Tengine http proxy/ h/$1/ cpe:/a:alibaba:tengine/
match http-proxy m|^HTTP/1\.0 404 Not Found\r\nServer: BigIP\r\nConnection: close\r\n| p/F5 BIG-IP load balancer/ d/load balancer/
match http-proxy m|^HTTP/1\.0 503 Service Unavailable\r\nContent-Type: text/html\r\nContent-Length: 5\d\r\nExpires: now\r\nPragma: no-cache\r\nCache-control: no-cache,no-store\r\n\r\nThe service is not available\. Please try again later\.| p/Pound http reverse proxy/ cpe:/a:apsis:pound/
match http-proxy m|^HTTP/1\.0 302 Found\r\nLocation: .*\r\nContent-Type: text/html\r\nContent-Length: \d+\r\n\r\n<html><head><title>Redirect</title></head><body><h1>Redirect</h1><p>You should go to <a href="[^"]+">here</a></p></body></html>| p/Pound http reverse proxy/ cpe:/a:apsis:pound/
match http-proxy m|^HTTP/1\.0 501 Not Implemented\r\nContent-Type: text/html\r\nContent-Length: 2\d\r\nExpires: now\r\nPragma: no-cache\r\nCache-control: no-cache,no-store\r\n\r\nThis method may not be used\.| p/Pound http reverse proxy/ cpe:/a:apsis:pound/
match http-proxy m|^HTTP/1\.0 403 Forbidden\r\nConnection: close\r\nContent-Length: 51\r\nContent-type: text/html\r\n\r\nAccess denied: authentication configuration missing| p/Smoothwall http proxy/ d/firewall/ cpe:/o:smoothwall:smoothwall/
match http-proxy m|^HTTP/1\.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Hola Unblocker"\r\nDate: .*\r\nConnection: close\r\n\r\n| p/Hola Unblocker http proxy/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\nContent-Length: 21\r\nContent-Type: text/html; charset=utf-8\r\nVia: 1\.1 ([\w.-]+)\r\nDate: .*\r\n\r\nBad Request to URI: /| p/LittleProxy http proxy/ h/$1/ cpe:/a:adamfisk:littleproxy/
match http-proxy m|^HTTP/1\.1 400 Bad request\r\nContent-Length: 53\r\nContent-Type: text/html\r\n\r\nCan't do transparent proxying without a Host: header\.|
match http-proxy m|^HTTP/1.[01] 407 | i/proxy authentication required/
match http-proxy m|^HTTP/1\.1 503 Service Unavailable\r\ndate: .*\r\nconnection: close\r\n\r\n<html><body><pre><h1>Service unavailable</h1></pre></body></html>\n| p/HTTP Replicator proxy/
match http-proxy m|^HTTP/1\.1 400 Bad Request\r\n.*This is a WebSEAL error message template file\.|s p/IBM WebSEAL reverse http proxy/ d/proxy server/
match http-proxy m|^HTTP/1\.1 200 OK\r.*\nAllow: GET,HEAD,POST,OPTIONS\r.*\nServer: Oracle-Application-Server-(\w+) Oracle-Web-Cache \(|s p/Oracle Web Cache http proxy/ v/$1/ cpe:/a:oracle:application_server_web_cache:$1/
match http-proxy m|^HTTP/1\.1 405 Method Not Allowed\r\nContent-Length: 1059\r\nContent-Type: text/html; charset=utf-8\r\n\r\n$| p/XX-Net web proxy tool/
match http-proxy m|^HTTP/1\.1 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nPragma: no-cache\r\nContent-Length: \d+\r\nSet-Cookie: f5[a-z]+=[A-Z]+; HttpOnly; secure\r\n\r\n<html><head><title>Request Rejected</title>| p/F5 BIG-IP load balancer http-proxy/ d/load balancer/
match http-proxy m|^HTTP/1\.1 400 Bad Request \( The data is invalid\.  \)\r\n| p/Microsoft ISA Server http proxy/ o/Windows/ cpe:/a:microsoft:isa_server/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 503 Service Unavailable\r\ndate: .*\r\nconnection: close\r\n\r\n<html><body><pre><h1>Service unavailable</h1></pre></body></html>\n| p/HTTP Replicator proxy/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nContent-Length: 103\r\nConnection: close\r\n\r\n<html><body> <h2>Mikrotik HttpProxy</h2>\n\r<hr>\n\r<h2>\n\rError: 400 Bad Request\r\n\r\n</h2>\n\r</body></html>\n\r$| p/MikroTik HttpProxy/ d/router/
match http-proxy m|^RTSP/1\.0 400 Bad Request\r\nServer: PanWeb Server/([\w._-]+)\r\n(?:[^\r\n]+\r\n)*?Keep-Alive: timeout=60, max=2000\r\nContent-Type: text/html\r\nContent-length: 130\r\n\r\n<HTML><HEAD><TITLE>Document Error: Bad Request</TITLE>|s p/Palo Alto PanWeb httpd/ v/$1/ d/proxy server/ cpe:/a:paloaltonetworks:panweb:$1/
match http-proxy m|^HTTP/1\.0 200 OK\r\nCache-Control: no-store\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nX-Bypass-Cache: Application and Content Networking System Software ([\d.]+)\r\n| p/Cisco ACNS outbound proxying/ v/$1/ cpe:/a:cisco:application_and_content_networking_system_software:$1/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Warning: Non-HTTP Protocol</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ cpe:/a:i2p_project:i2p/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Warnung: Kein HTTP Protokoll</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/German/ cpe:/a:i2p_project:i2p::::de/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Advertencia: Protocolo no HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Spanish/ cpe:/a:i2p_project:i2p::::es/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Avertissement : protocole non HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/French/ cpe:/a:i2p_project:i2p::::fr/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Peringatan: Protokol Non-HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Indonesian/ cpe:/a:i2p_project:i2p::::id/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Waarschuwing: non-HTTP protocol</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Dutch/ cpe:/a:i2p_project:i2p::::nl/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Ostrzeżenie: protokół inny niż HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Polish/ cpe:/a:i2p_project:i2p::::pl/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Aviso: Protocolo não-HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Brazilian Portuguese/ cpe:/a:i2p_project:i2p::::pt_br/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Aviso: Protocolo fora do padrão HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Portuguese/ cpe:/a:i2p_project:i2p::::pt/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Atenție: protocolul Non-HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Romanian/ cpe:/a:i2p_project:i2p::::ro/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Предупреждение: Протокол не HTTP</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Russian/ cpe:/a:i2p_project:i2p::::ru/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?Varning: Ej HTTP Protokoll</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Swedish/ cpe:/a:i2p_project:i2p::::sv/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\n.*<title>(?:I2P )?警告：非 HTTP 协议</title>\r\n<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\" ?>\r\n|s p/I2P anonymizing http proxy/ i/Chinese/ cpe:/a:i2p_project:i2p::::zh/
match http-proxy m|^HTTP/1\.1 403 Bad Protocol\r\nContent-Type: text/html; charset=UTF-8\r\nCache-control: no-cache\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n.*<link rel=\"shortcut icon\" href=\"http://proxy\.i2p/themes/console/images/favicon\.ico\"|s p/I2P anonymizing http proxy/
match http-proxy m|^HTTP/1\.0 503\r\nServer: Charles\r\n| p/Charles http proxy/
match http-proxy m|^ 400 badrequest\r\n.*<title>McAfee Web Gateway - Notification - </title>|s p/McAfee Web Gateway http proxy/ d/proxy server/ cpe:/a:mcafee:web_gateway/
match http-proxy m|^<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4\.01 Transitional//EN" "http://www\.w3\.org/TR/html4/loose\.dtd">\n<HTML><HEAD>\n<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8"> \n<TITLE>\xe9\x94\x99\xe8\xaf\xaf\xef\xbc\x9a\xe6\x82\xa8\xe6\x89\x80\xe8\xaf\xb7\xe6\xb1\x82\xe7\x9a\x84\xe7\xbd\x91\xe5\x9d\x80\xef\xbc\x88URL\xef\xbc\x89\xe6\x97\xa0\xe6\xb3\x95\xe8\x8e\xb7\xe5\x8f\x96</TITLE>\n<STYLE type="text/css"><!--BODY\{background-color:#ffffff;font-family:verdana,sans-serif\}PRE\{font-family:sans-serif\}--></STYLE>\n</HEAD>| p/Squid/ i/Chinese/ cpe:/a:squid-cache:squid::::zh/
match http-proxy m|^ 400 badrequest\r\nVia: 1\.0 ([\w.-]+) \(McAfee Web Gateway ([\w._-]+)\)\r\nConnection: Close\r\n| p/McAfee Web Gateway/ v/$2/ i/Via $1/ cpe:/a:mcafee:web_gateway:$2/
match http-proxy m|^HTTP/1\.1 400\r\nConnection: close\r\n\r\nBad request syntax \('\\x16\\x03\\x00\\x00S\\x01\\x00\\x00O\\x03\\x00\?G\\xd7\\xf7\\xba,\\xee\\xea\\xb2${backquote}~\\xf3\\x00\\xfd\\x82\{\\xb9\\xd5\\x96\\xc8w\\x9b\\xe6\\xc4\\xdb<=\\xdbo\\xef\\x10n\\x00\\x00\(\\x00\\x16\\x00\\x13\\x00'\)| p/XX-Net web proxy tool/
match http-proxy m|^HTTP/1\.0 414 Request URI too long\r\nContent-Type: text/html\r\nContent-Length: 23\r\nExpires: now\r\nPragma: no-cache\r\nCache-control: no-cache,no-store\r\n\r\nRequest URI is too long| p/Pound http reverse proxy/ cpe:/a:apsis:pound/
match http-proxy m|^HTTP/1\.0 404 Error\r\n.*<HTML><HEAD><TITLE>Extra Systems Proxy Server</TITLE>|s p/Extra Systems http proxy/ o/Windows/ cpe:/o:microsoft:windows/a
match http-proxy m|^HTTP/1\.1 502 Bad Gateway\r\nConnection : close\r\n.*\n<title>The requested URL could not be retrieved</title>\n<link href=\"http://passthrough\.fw-notify\.net/static/default\.css\"|s p/Astaro firewall http proxy/ d/firewall/ cpe:/a:astaro:security_gateway_software/
match http-proxy m|^HTTP/1\.0 404 Not Found\r\nDate: .*\r\nServer: PanWeb Server/ - \r\n| p/Palo Alto PanWeb httpd/ d/firewall/ cpe:/a:paloaltonetworks:panweb/
match http-proxy m|^HTTP/1\.0 400 Bad Request\r\nServer: squid/([\w._+-]+)\r\n| p/Squid/ v/$1/ cpe:/a:squid-cache:squid:$1/
match http-proxy-ctrl m|^WWWOFFLE Server Status\n-*\nVersion *: (\d.*)\n| p/WWWOFFLE proxy control/ v/$1/
match http-proxy-ctrl m|^WWWOFFLE Incorrect Password\n| p/WWWOFFLE proxy control/ i/Unauthorized/
match http-proxy m|^<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2\.0//EN\">\n<HTML><HEAD><TITLE>Error</TITLE></HEAD>\n<BODY><h2>400 Can not find method and URI in request</h2>\r\nWhen trying to load <a href=\"smartcache://url-parse-error\">smartcache://url-parse-error</a>\.\n<hr noshade size=1>\r\nGenerated by smart\.cache \(<a href=\"http://scache\.sourceforge\.net/\">Smart Cache ([\w._-]+)</a>\)\r\n</BODY></HTML>\r\n$| p/Smart Cache http-proxy/ v/$1/


match http m|^HTTP\/[0-9\.]+\s+[0-9]{3}\b.*$| p/HTTP/
match ajp13 m|^AB\0\x13\x04\x01\x90\0\x0bBad Request\0\0\0AB\0\x02\x05\x01$| p/Apache Jserv/

softmatch smtp m|^220[\s-].*smtp[^\r]*\r\n|i
softmatch ftp m=^220[\s-].*(ftp|FileZilla)[^\r]*\r\n=i

match ftp m|^220 .*\r\n| p/FTP/ 
match ftp m|^220[- ]+.*\r\n| p/FTP/ 
match ftp m|^220.*\r\n| p/FTP/

match pop3 m|^\+OK.*| p/POP3/



# RFC 1939 suggests <process-ID.clock@hostname> for the timestamp
softmatch pop3 m|^\+OK [^<]+ <[\d.]+@([\w.-]+)>\r\n$| h/$1/
# otherwise, just softmatch anything
softmatch pop3 m|^\+OK [-\[\]\(\)!,/+:<>@.\w ]+\r\n$|

match ssh m|^SSH-[0-9\.]+-.*\r\n| p/SSH/

match mysql m|^[0-9a-f]{4}[^0-9a-f]*[5-8]\.[0-9]+\..*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*MySQL.*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*MariaDB.*| p/MySQL/
match mysql m|^[0-9a-f]{4}.*server version.*| p/MySQL/
match mysql m|^[0-9a-f]{4}| p/MySQL/

match mysql m|^.\0\0\0\n(.\\.[-_~.+\\w]+)\0| p/MySQL/
match mysql m|^.\0\0\0ÿj\x04'[\\d.]+' .* MySQL| p/MySQL/
match mysql m|^\x48\0\0\0.*allowed.*| p/MySQL/

match telnet m|^\xFF| p/Telnet/
match imap m|^\* OK.*| p/IMAP/
match svnserve m|^\( success \( \d \d \( (?:ANONYMOUS )?\) \( | p/Subversion/ cpe:/a:apache:subversion/

match rsync m|^@RSYNCD: (\d+)| i/protocol version $1/
# Synology Network Backup Service (rsync backup)
match rsync m|^@ERROR: protocol startup error\n|


##############################NEXT PROBE##############################
# SSLv3 ClientHello probe. Will be able to reliably identify the SSL version
# used, unless the server is running SSLv2 only. Note that it will also detect
# TLSv1-only servers, based on a failed handshake alert.
Probe TCP SSLSessionReq q|\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2${backquote}~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0${backquote}\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0|
rarity 1
ports 261,271,322,324,443,444,448,465,548,563,585,636,684,853,989,990,992-995,1241,1311,1443,2000,2221,2252,2376,2443,3443,4433,4443,4444,4911,5061,5443,5550,5868,5986,6251,6443,6679,6697,7000,7210,7272,7443,8009,8181,8194,8443,8531,8883,9001,9443,10443,14443,15002,44443,60443
fallback GetRequest

# Unknown service on Vingtor-Stentofon IP intercom echoes only up to the first \n, so softmatching until we know more.
softmatch echo m|^\x16\x03\0\0S\x01\0\0O\x03\0\?G\xd7\xf7\xba,\xee\xea\xb2${backquote}~\xf3\0\xfd\x82\{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0\(\0\x16\0\x13\0\n|

# OpenSSL/0.9.7aa, 0.9.8e
match ssl m|^\x16\x03\0\0J\x02\0\0F\x03\0| p/OpenSSL/ i/SSLv3/ cpe:/a:openssl:openssl/

# Microsoft-IIS/5.0 - note that OpenSSL must go above this one because this is more general
match ssl m|^\x16\x03\0..\x02\0\0F\x03\0|s p/Microsoft IIS SSL/ o/Windows/ cpe:/a:microsoft:internet_information_services/ cpe:/o:microsoft:windows/a
# Novell Netware 6 Enterprise Web server 5.1 https
# Novell Netware Ldap over SSL or enterprise web server 5.1 over SSL
match ssl m|^\x16\x03\0\0:\x02\0\x006\x03\0| p/Novell NetWare SSL/ o/NetWare/ cpe:/o:novell:netware/a
# Cisco IDS 4.1 Appliance
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03\0\xd10:\xbd\\\x8e\xe3\x15\x1c\x0fZ\xe4\x04\x87\x07\xc0\x82\xa9\xd4\x0e\x9c1LXk\xd1\xd2\x0b\x1a\xc6/p\0\0\n\0\x16\x03\0\x026\x0b\0\x022\0| p/Cisco IDS SSL/ d/firewall/
# PGP Corporation Keyserver Web Console 7.0 - custom Apache 1.3
# PGP LDAPS Keyserver 8.X
match ssl m|^\x16\x03\0\0\+\x02\0\0'\x03\0...\?|s p/PGP Corporation product SSL/
# Unreal IRCd SSL
# RemotelyAnywhere
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03\0\?|
# Tumbleweed SecureTransport 4.1.1 Transaction Manager Secure Port on Solaris
# Dell Openmanage
match ssl m|^\x15\x03[\x01\x00]\0\x02\x01\0$| p/multi-vendor SSL/
# Probably Oracle https?
match ssl m|^}\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0| p/Oracle https/
match ssl m|^\x15\x03\0\0\x02\x02\(31666:error:1408A0C1:SSL routines:SSL3_GET_CLIENT_HELLO:no shared cipher:s3_srvr\.c:881:\n| p/Webmin SSL Control Panel/
match ssl m|^20928:error:140760FC:SSL routines:SSL23_GET_CLIENT_HELLO:unknown protocol:s23_srvr\.c:565:\n| p/qmail-pop3d behind stunnel/ cpe:/a:djb:qmail/

match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03\0B| p/Tor over SSL/ cpe:/a:torproject:tor/
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03.*IOS-Self-Signed-Certificate|s p/Cisco IOS ssl/ d/router/
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03.*\nCalifornia.*\tPalo Alto.*\x0cVMware, Inc\..*\x1bVMware Management Interface|s p/VMware management interface SSLv3/
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03.*\x0edropbox-client0|s p/Dropbox client SSLv3/ cpe:/a:dropbox:dropbox/
match ssl m|^\x16\x03\0\0\*\x02\0\0&\x03.*vCenterServer_([\w._-]+)|s p/VMware ESXi Server httpd/ v/$1/ cpe:/o:vmware:esxi:$1/

# Alert (Level: Fatal, Description: Protocol Version|Handshake Failure)
match ssl m|^\x15\x03[\x00-\x03]\0\x02\x02[F\x28]|
# Alert (Level: Warning, Description: Close Notify)
match ssl m|^\x15\x03[\x00-\x03]\0\x02\x01\x00|

# Sophos Message Router
match ssl/sophos m|^\x16\x03\0.*Router\$([a-zA-Z0-9_-]+).*Sophos EM Certification Manager|s p/Sophos Message Router/ h/$1/
match ssl/sophos m|^\x16\x03\0.*Sophos EM Certification Manager|s p/Sophos Message Router/

match ssl/openvas m|^\x16\x03\x01\0J\x02\0\0F\x03\x01| p/OpenVAS server/

# Generic: TLSv1.3 ServerHello
match ssl m|^\x16\x03\x03..\x02...\x03\x03|s p/TLSv1.2/
# Generic: TLSv1.2 ServerHello
match ssl m|^\x16\x03\x02..\x02...\x03\x02|s p/TLSv1.1/
# Generic: TLSv1.1 ServerHello
match ssl m|^\x16\x03\x01..\x02...\x03\x01|s p/TLSv1.0/

# Generic: SSLv3 ServerHello
match ssl m|^\x16\x03\0..\x02...\x03\0|s p/SSLv3/
# SSLv3 - TLSv1.3 Alert
match ssl m|^\x15\x03[\0-\x04]\0\x02[\x01\x02].$|s

match adabas m|^,\0,\0\x03\x02\0\0G\xd7\xf7\xbaO\x03\0\?\x05\0\0\0\0\x02\x18\0\xfd\x0b\0\0<=\xdbo\xef\x10n \xd5\x96\xc8w\x9b\xe6\xc4\xdb$| p/ADABAS database/


##############################NEXT PROBE##############################
# Redis key-value store
Probe TCP redis-server q|*1\r\n$4\r\ninfo\r\n|
rarity 8
ports 6379
match redis m|-ERR operation not permitted\r\n|s p/Redis key-value store/ cpe:/a:redislabs:redis/
match redis m|^\$\d+\r\n(?:#[^\r\n]*\r\n)*redis_version:([.\d]+)\r\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/


##############################NEXT PROBE##############################
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
ports 21,23,35,43,79,98,110,113,119,199,214,264,449,505,510,540,587,616,628,666,731,771,782,1000,1010,1040-1043,1080,1212,1220,1248,1302,1400,1432,1467,1501,1505,1666,1687-1688,2010,2024,2600,3000,3005,3128,3310,3333,3940,4155,5000,5400,5432,5555,5570,6112,6432,6667-6670,7144,7145,7200,7780,8000,8138,9000-9003,9801,11371,11965,13720,15000-15002,18086,19150,26214,26470,31416,30444,34012,56667
sslports 989,990,992,995

match http m|^HTTP\/[0-9\.]+\s+[0-9]{3}\b.*$| p/HTTP/
softmatch smtp m=^220[\s-].*(smtp|mail)[^\r]*\r\n=i
softmatch ftp m=^220[\s-].*(ftp|FileZilla)[^\r]*\r\n=i

match ftp m|^220 .*\r\n530 Please login with USER and PASS\.\r\n530 Please login with USER and PASS\.\r\n| p/vsftpd (before 2.0.8) or WU-FTPD/ cpe:/a:vsftpd:vsftpd/

match pop3 m|^\+OK.*| p/POP3/
match imap m|^\* OK.*| p/IMAP/


softmatch gopher m|^i\t?[\x20-\x7f]+\tfake\t\(NULL\)\t0\r\n| p/Pygopherd or Phricken/
softmatch gopher m|^[0-9ghisIT](?:\t?[\x20-\x7f]+\t){3}[0-9]+\r\n|

##############################NEXT PROBE##############################
Probe TCP LDAPSearchReq q|\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00|
rarity 6
ports 256,257,389,390,1702,3268,3892,11711
sslports 636,637,3269,11712

match ldap m|^0\x84\0\0..\x02\x01.*dsServiceName1\x84\0\0\0.\x04.CN=NTDS\x20Settings,CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites,CN=Configuration,DC=([^,]+),DC=([^,]+)0\x84\0|s p/Microsoft Windows Active Directory LDAP/ i/Domain: $3.$4, Site: $2/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
match ldap m|^0\x84\0\0..\x02\x01.*dsServiceName1\x84\0\0\0.\x04.CN=NTDS\x20Settings,CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites,CN=Configuration,DC=([^,]+),DC=([^,]+),DC=([^,]+)0\x84\0|s p/Microsoft Windows Active Directory LDAP/ i/Domain: $3.$4.$5, Site: $2/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
match ldap m|^0\x82\x05.\x02\x01.*vmwPlatformServicesControllerVersion1\x07\x04\x05([\d.]+)0.\x04.*\nserverName1.\x04.cn=([^,.]+)|s p/VMware vCenter or PSC LDAP/ v/PSCv $1/ h/$2/ cpe:/a:vmware:server/
match ldap m|^unable to set certificate file\n6292:error:02001002:system library:fopen:No such file or directory:bss_file\.c:| p/OpenLDAP over SSL/ i/broken/ cpe:/a:openldap:openldap/
match ldap m|^0%\x02\x01\x01a \n\x010\x04\0\x04\x19anonymous bind disallowed$| p/OpenLDAP/ i/access denied/ cpe:/a:openldap:openldap/
match ldap m|^02\x02\x01\x01a-\n\x01\x02\x04\0\x04&requested protocol version not allowed$| p/OpenLDAP/ v/2.1.X/ cpe:/a:openldap:openldap:2.1/

match ldap m|^\x30([^\x00-\x1F]+)| p/ldap/



##############################NEXT PROBE##############################
Probe TCP oracle-tns q|\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))|
rarity 7
ports 1035,1521,1522,1525,1526,1574,1748,1754,14238,20000

match http m|^HTTP/1\.0 400 Bad Request\r\nDate: .*\r\nServer: Boa/([\w._-]+)\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Request</H1>\nYour client has issued a malformed or illegal request\.\n</BODY></HTML>\n$| p/Boa httpd/ v/$1/ i/Prolink ADSL router/ d/broadband router/ cpe:/a:boa:boa:$1/

match iscsi m|^\x3f\x80\x04\0\0\0\x00\x30\0\0\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\xf7\0\0\0\0\0\0\0\0\0\0\0\0\0Z\0\0\x01\0\0\0\x016\x01\x2c\0\0\x08\0\x7f\xff\x7f\x08\0\0\0\x01\0\x20\0\x3a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x004\xe6\0\0$| p/iSCSI/
match iscsi m|^\x3f\x80\x04\0\0\0\x00\x30\0\0\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00\x00\0\0\0\0\0\0\0\0\0\0\0\0\0Z\0\0\x01\0\0\0\x016\x01\x2c\0\0\x08\0\x7f\xff\x7f\x08\0\0\0\x01\0\x20\0\x3a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x004\xe6\0\0$| p/HP StorageWorks D2D backup system iSCSI/ d/storage-misc/

match palm-hotsync m|^\x01.\0\0\0\x14\x11\x01\0\0\0\0\0\0\0\x20\0\0\0\x06\x01\0..\0\0$|s p/Palm Pilot HotSync/

match oracle-tns m|^\0.\0\0[\x02\x04]\0\0\0.*TNSLSNR for ([-.+/ \w]{2,24}): Version ([-\d.]+) - Production|s p/Oracle TNS Listener/ v/$2/ i/for $1/
match dbsnmp m|^\0.\0\0\x02\0\0\0.*\(IAGENT = \(AGENT_VERSION = ([\d.]+)\)\(RPC_VERSION = ([\d.]+)\)\)|s p/Oracle Intelligent Agent/ v/$1/ i/RPC v$2/
match oracle m|^\0\x20\0\0\x02\0\0\0\x016\0\0\x08\0\x7f\xff\x01\0\0\0\0\x20|s p/Oracle Database/ cpe:/a:oracle:database_server/
match oracle m|^\+\0\0\0$| p/Oracle Database/ cpe:/a:oracle:database_server/
match oracle-tns m|^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1189\)\(ERROR_STACK=\(ERROR=\(CODE=1189\)\(EMFI=4\)\)| p/Oracle TNS Listener/ i/unauthorized/
match oracle-tns m|^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1194\)\(ERROR_STACK=\(ERROR=\(CODE=1194\)\(EMFI=4\)\)\)\)| p/Oracle TNS Listener/ i/insecure transport/
match oracle-tns m|^..\0\0\x04\0\0\0\"\0..\(DESCRIPTION=\(ERR=12504\)\)\0| p/Oracle TNS listener/ i/requires service name/
softmatch oracle-tns m|^\0.\0\0[\x02\x04]\0\0\0.*\([ABD-Z]|s p/Oracle TNS Listener/
match dbsnmp m|^\0,\0\0\x04\0\0\0\"\0\0 \(CONNECT_DATA=\(COMMAND=version\)\)| p/Oracle DBSNMP/

match hp-radia m|^\xff\xff$| p/HP Radia configuration server/

match winbox m|^.\x01\0.M2\x01\0\xff\x88\0\0\x02\0\xff\x88[\x01\x02]\0|s p/MikroTik WinBox/ cpe:/a:mikrotik:winbox/

`
