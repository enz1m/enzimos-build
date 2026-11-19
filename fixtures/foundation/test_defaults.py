#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real service/protocol tests confined to this guest and its own network namespaces."""
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import termios
import time
from native import run,output
import backup
import maintenance

BASE=Path('/var/lib/enzimos-control/defaults-tests')
PROCESSES=[]
CHECK=None


def spawn(args,label):
    log=(BASE/(label+'.log')).open('w')
    p=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,text=True,start_new_session=True)
    PROCESSES.append((p,log));return p

def stop(p):
    if p.poll() is None:
        os.killpg(p.pid,signal.SIGTERM)
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)

def wait(predicate,description,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return
        time.sleep(0.5)
    raise AssertionError('timeout: '+description)

def command_ok(args):return subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0

def accounts():
    CHECK(output(['id','-u','enzimos-admin'])=='1000','ordinary admin UID')
    CHECK('wheel' in output(['id','-nG','enzimos-admin']).split(),'admin wheel membership')
    CHECK('wheel' not in output(['id','-nG','enzimos-user']).split(),'ordinary user has wheel access')
    shadow=next(x for x in Path('/etc/shadow').read_text().splitlines() if x.startswith('root:')).split(':')[1]
    CHECK(shadow.startswith(('!','*')),'root password is not locked')
    run(['visudo','-c'],stdout=subprocess.DEVNULL)
    for user in ('enzimos-admin','enzimos-user'):
        run(['runuser','-u',user,'--','sudo','-K'])
        CHECK(not command_ok(['runuser','-u',user,'--','sudo','-n','true']),'passwordless escalation')
    good=subprocess.run(['runuser','-u','enzimos-admin','--','sudo','-S','-p','','id','-u'],input='ENZIMOS-PUBLIC-LAB-ADMIN\n',capture_output=True,text=True)
    CHECK(good.returncode==0 and good.stdout.strip()=='0','authenticated admin sudo failed')
    bad=subprocess.run(['runuser','-u','enzimos-user','--','sudo','-S','-p','','id','-u'],input='ENZIMOS-PUBLIC-LAB-USER\n',capture_output=True,text=True)
    CHECK(bad.returncode!=0,'non-admin sudo succeeded')
    denied=subprocess.run(['runuser','-u','enzimos-user','--','python','/usr/lib/enzimos/backup.py','history','--automatic'],capture_output=True,text=True)
    CHECK(denied.returncode!=0 and 'root authorization required' in denied.stderr,'unprivileged internal API accepted')
    CHECK(not command_ok(['runuser','-u','enzimos-user','--','pkexec','--disable-internal-agent','id','-u']),'polkit bypass without authentication')
    pid,fd=pty.fork()
    if pid==0:
        os.execv('/usr/bin/runuser',['runuser','-u','enzimos-admin','--','python',str(Path(__file__).with_name('polkit_probe.py'))])
    transcript=b'';sent=False;status=None;end=time.monotonic()+90
    try:
        while time.monotonic()<end:
            if select.select([fd],[],[],0.2)[0]:
                try:data=os.read(fd,4096)
                except OSError:break
                if not data:break
                transcript+=data
                if b'Password:' in transcript and not sent:
                    ready=time.monotonic()+5
                    while termios.tcgetattr(fd)[3] & termios.ECHO and time.monotonic()<ready:time.sleep(0.05)
                    CHECK(not termios.tcgetattr(fd)[3] & termios.ECHO,'text agent did not disable terminal echo')
                    os.write(fd,b'ENZIMOS-PUBLIC-LAB-ADMIN\n');sent=True
            done,st=os.waitpid(pid,os.WNOHANG)
            if done:status=st;break
        if status is None:
            for _ in range(20):
                done,st=os.waitpid(pid,os.WNOHANG)
                if done:status=st;break
                time.sleep(0.1)
        print('ENZIMOS_POLKIT_TEST_TRANSCRIPT\n'+transcript.decode(errors='replace'),flush=True)
        plain=re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]',b'',transcript)
        CHECK(status is not None and os.waitstatus_to_exitcode(status)==0 and sent and re.search(rb'(?m)^0\r?$',plain),'polkit authenticated text-agent path failed')
    finally:
        os.close(fd)
        if status is None:
            try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
            except ProcessLookupError:pass
        (BASE/'polkit.txt').write_bytes(transcript)
    return {'admin_uid':1000,'root_locked':True,'sudo_authenticated':True,'polkit_authenticated':True,'unprivileged_denied':True}


def ns(name,*args):return ['ip','netns','exec',name,*args]

def network_setup():
    for index,letter in ((1,'a'),(2,'b')):
        peer='enz-peer-'+letter;interface='enz-net-'+letter
        run(['ip','netns','add',peer]);run(['ip','link','add',interface,'type','veth','peer','name','eth0','netns',peer])
        run(ns(peer,'ip','link','set','lo','up'));run(ns(peer,'ip','link','set','eth0','up'))
        run(ns(peer,'ip','address','add',f'10.203.{index}.1/24','dev','eth0'))
        run(ns(peer,'ip','-6','address','add',f'fd00:203:{index}::1/64','dev','eth0'))
        config=Path('/etc/dnsmasq.d')/('enzimos-peer-'+letter+'.conf');config.parent.mkdir(exist_ok=True)
        text=f'interface=eth0\nbind-interfaces\nno-resolv\nno-hosts\nlog-queries\nlog-dhcp\npid-file=/run/dnsmasq/enz-{letter}.pid\n'
        if letter=='a':
            text+='dhcp-range=10.203.1.10,10.203.1.10,255.255.255.0,1h\ndhcp-option=3\ndhcp-option=option:dns-server,10.203.1.1\ndhcp-option=option:domain-name,a.test\ndhcp-leasefile=/var/lib/misc/dnsmasq.leases\n'
            text+='address=/a.test/192.0.2.11\naddress=/b.test/192.0.2.99\nhost-record=nts.a.test,10.203.1.1\nhost-record=wrong.a.test,10.203.1.1\n'
        else:text+='address=/b.test/198.51.100.22\naddress=/a.test/198.51.100.99\n'
        config.write_text(text)
        Path('/run/dnsmasq').mkdir(exist_ok=True)
        spawn(ns(peer,'dnsmasq','--no-daemon','--conf-file='+str(config)),'dns-'+letter)
        args=['nmcli','connection','add','type','ethernet','ifname',interface,'con-name',interface,
              'ipv4.never-default','yes','ipv6.method','manual','ipv6.addresses',f'fd00:203:{index}::10/64','ipv6.never-default','yes']
        if letter=='a':args+=['ipv4.method','auto']
        else:args+=['ipv4.method','manual','ipv4.addresses','10.203.2.10/24','ipv4.dns','10.203.2.1','ipv4.dns-search','~b.test']
        run(args);run(['nmcli','--wait','45','connection','up',interface])


def dns_test():
    CHECK(Path('/etc/resolv.conf').is_symlink() and os.readlink('/etc/resolv.conf')=='/run/systemd/resolve/stub-resolv.conf','resolver ownership')
    CHECK('10.203.1.10/24' in output(['nmcli','-g','IP4.ADDRESS','device','show','enz-net-a']),'DHCP lease absent')
    CHECK('10.203.1.1' in output(['resolvectl','dns','enz-net-a']),'DHCP DNS not passed to resolved')
    run(['resolvectl','flush-caches'])
    a=output(['resolvectl','query','proof.a.test']);b=output(['resolvectl','query','proof.b.test'])
    CHECK('192.0.2.11' in a and '198.51.100.22' in b,'split DNS used wrong link')
    CHECK(not output(['ip','route','show','default']) and not output(['ip','-6','route','show','default']),'fixture accidentally has a default route')
    run(['nmcli','connection','down','enz-net-b']);run(['resolvectl','flush-caches'])
    down=subprocess.run(['resolvectl','query','uncached.b.test'],capture_output=True,text=True,timeout=20)
    CHECK('198.51.100.22' not in down.stdout,'disconnected link retained stale DNS answer')
    run(['nmcli','--wait','45','connection','up','enz-net-b']);run(['resolvectl','flush-caches'])
    CHECK('198.51.100.22' in output(['resolvectl','query','again.b.test']),'split DNS did not recover')
    return {'dhcp':True,'split_dns':True,'disconnect_reconnect':True,'default_routes':False}

SERVER_CODE='''import selectors,socket,os
s=selectors.DefaultSelector()
for family,kind,port in [(socket.AF_INET,socket.SOCK_STREAM,18555),(socket.AF_INET6,socket.SOCK_STREAM,18556),(socket.AF_INET,socket.SOCK_DGRAM,18557),(socket.AF_INET6,socket.SOCK_DGRAM,18558)]:
 x=socket.socket(family,kind)
 if family==socket.AF_INET6:x.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 x.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);x.bind(('0.0.0.0' if family==socket.AF_INET else '::',port))
 if kind==socket.SOCK_STREAM:x.listen()
 s.register(x,selectors.EVENT_READ,kind)
print('ENZIMOS_ECHO_SERVER_READY uid='+str(os.getuid()),flush=True)
while True:
 for key,_ in s.select():
  x=key.fileobj
  if key.data==socket.SOCK_STREAM:
   c,_=x.accept();c.settimeout(2)
   try:c.sendall(b'OK' if c.recv(128)==b'LAB-TOKEN' else b'DENIED')
   finally:c.close()
  else:
   data,addr=x.recvfrom(128);x.sendto(b'OK' if data==b'LAB-TOKEN' else b'DENIED',addr)
'''


def request(ip,port,udp=False,token='LAB-TOKEN'):
    code="import socket,sys\ns=socket.socket(socket.AF_INET6 if ':' in %r else socket.AF_INET,%s)\ns.settimeout(2)\ntry:\n s.connect((%r,%d));s.send(%r);print(s.recv(128).decode())\nexcept OSError as e:\n print('NETWORK_BLOCKED '+str(e));sys.exit(10)\n"%(ip,'socket.SOCK_DGRAM' if udp else 'socket.SOCK_STREAM',ip,port,token.encode())
    return subprocess.run(ns('enz-peer-a','python','-c',code),capture_output=True,text=True,timeout=30)


def firewall_test():
    CHECK(output(['firewall-cmd','--get-default-zone'])=='public','default zone not restrictive public')
    CHECK(output(['firewall-cmd','--get-zone-of-interface=enz-net-a'])=='public','private DHCP implicitly granted trust')
    server=spawn(['runuser','-u','enzimos-user','--','python','-u','-c',SERVER_CODE],'echo-server')
    wait(lambda:'ENZIMOS_ECHO_SERVER_READY uid=1001' in (BASE/'echo-server.log').read_text(),'unprivileged fixture listener ready',90)
    targets=[('10.203.1.10',18555,False),('fd00:203:1::10',18556,False),('10.203.1.10',18557,True),('fd00:203:1::10',18558,True)]
    for ip,port,udp in targets:CHECK(request(ip,port,udp).returncode==10,'public-zone service reachable or probe invalid')
    run(['nmcli','connection','modify','enz-net-a','connection.zone','trusted']);run(['nmcli','device','reapply','enz-net-a'])
    wait(lambda:output(['firewall-cmd','--get-zone-of-interface=enz-net-a'])=='trusted','explicit trust application')
    for ip,port,udp in targets:
        r=request(ip,port,udp);CHECK(r.returncode==0 and r.stdout.strip()=='OK','trusted service failed')
    CHECK(request('10.203.1.10',18555,token='WRONG').stdout.strip()=='DENIED','firewall bypassed fixture authentication')
    run(['nmcli','connection','modify','enz-net-a','connection.zone','public']);run(['nmcli','device','reapply','enz-net-a'])
    wait(lambda:output(['firewall-cmd','--get-zone-of-interface=enz-net-a'])=='public','trust removal')
    for ip,port,udp in targets:CHECK(request(ip,port,udp).returncode==10,'new flow allowed or probe invalid after return to public')
    stop(server)
    return {'ipv4_tcp_udp':True,'ipv6_tcp_udp':True,'implicit_trust':False,'application_authentication_separate':True,
            'scope':'new flows; existing conntrack sessions are a separate revocation qualification'}


def udp_count():
    rules=json.loads(output(['nft','-j','list','table','inet','enz_nts_probe']))['nftables']
    return sum(e['counter']['packets'] for r in rules if 'rule' in r for e in r['rule']['expr'] if 'counter' in e)


def nts_test():
    pki=Path('/etc/enzimos-lab/pki');pki.mkdir(parents=True,exist_ok=True)
    def openssl(*args):run(['openssl',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(pki/'ca.key'),'-out',str(pki/'ca.crt'),'-days','2','-subj','/CN=enzimOS LAB ONLY CA')
    openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(pki/'server.key'),'-out',str(pki/'server.csr'),'-subj','/CN=nts.a.test')
    (pki/'extensions').write_text('subjectAltName=DNS:nts.a.test\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in',str(pki/'server.csr'),'-CA',str(pki/'ca.crt'),'-CAkey',str(pki/'ca.key'),'-CAcreateserial','-days','1','-out',str(pki/'server.crt'),'-extfile',str(pki/'extensions'))
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(pki/'wrong.key'),'-out',str(pki/'wrong.crt'),'-days','2','-subj','/CN=UNTRUSTED LAB CA')
    for p in pki.glob('*.key'):p.chmod(0o600)
    run(['chown','chrony:chrony',pki/'server.key'])
    for name in ('nts-server-lab','nts-client-lab'):
        d=Path('/var/lib/chrony')/name;d.mkdir(exist_ok=True);run(['chown','chrony:chrony',d])
    serverconf=Path('/etc/enzimos-lab/nts-server.conf')
    serverconf.write_text('local stratum 1\nallow 10.203.1.0/24\nbindaddress 10.203.1.1\nntsservercert /etc/enzimos-lab/pki/server.crt\nntsserverkey /etc/enzimos-lab/pki/server.key\nntsdumpdir /var/lib/chrony/nts-server-lab\npidfile /run/chrony/nts-server.pid\nbindcmdaddress /run/chrony/nts-server.sock\ncmdport 0\n')
    server=spawn(ns('enz-peer-a','chronyd','-n','-x','-f',str(serverconf)),'nts-server')
    override=Path('/run/systemd/system/chronyd.service.d/90-enzimos-lab.conf');override.parent.mkdir(parents=True,exist_ok=True)
    override.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/chronyd -n -f /etc/enzimos-lab/nts-client.conf\n')
    run(['systemctl','daemon-reload'])
    run(['nft','add','table','inet','enz_nts_probe'])
    run(['nft','add','chain','inet','enz_nts_probe','output','{ type filter hook output priority -10; policy accept; }'])
    run(['nft','add','rule','inet','enz_nts_probe','output','ip','daddr','10.203.1.1','udp','dport','123','counter'])
    client=Path('/etc/enzimos-lab/nts-client.conf')
    normal='server nts.a.test iburst nts minpoll 0 maxpoll 0\nauthselectmode require\nntstrustedcerts /etc/enzimos-lab/pki/ca.crt\nntsdumpdir /var/lib/chrony/nts-client-lab\ndriftfile /var/lib/chrony/drift-lab\nport 0\ncmdport 0\nbindcmdaddress /run/chrony/chronyd.sock\n'
    def restart(text):
        run(['systemctl','stop','chronyd'])
        d=Path('/var/lib/chrony/nts-client-lab')
        for p in d.iterdir():
            if p.is_file():p.unlink()
        client.write_text(text);run(['systemctl','start','chronyd'])
    def selected():
        r=subprocess.run(['chronyc','-n','sources'],capture_output=True,text=True)
        return r.returncode==0 and '^* 10.203.1.1' in r.stdout
    saved=time.time();mono=time.monotonic();clock_changed=False
    try:
        restart(normal);wait(selected,'authenticated NTS selection',90)
        auth=output(['chronyc','-n','authdata']);detail=output(['chronyc','-n','ntpdata','10.203.1.1'])
        CHECK('NTS' in auth and re.search(r'Authenticated\s*:\s*Yes',detail),'source not authenticated by NTS')
        (BASE/'nts-success.txt').write_text(auth+'\n'+detail)
        failures=[]
        for label,text in [('wrong-ca',normal.replace('/pki/ca.crt','/pki/wrong.crt')),('wrong-name',normal.replace('server nts.a.test','server wrong.a.test'))]:
            run(['systemctl','stop','chronyd']);before=udp_count();restart(text);time.sleep(10)
            CHECK(not selected() and udp_count()==before,'invalid certificate caused NTP fallback')
            failures.append(label)
        run(ns('enz-peer-a','nft','add','table','inet','enz_ke_failure'))
        run(ns('enz-peer-a','nft','add','chain','inet','enz_ke_failure','input','{ type filter hook input priority -10; policy accept; }'))
        run(ns('enz-peer-a','nft','add','rule','inet','enz_ke_failure','input','tcp','dport','4460','drop'))
        run(['systemctl','stop','chronyd']);before=udp_count();restart(normal);time.sleep(10)
        CHECK(not selected() and udp_count()==before,'unavailable NTS-KE caused plain NTP fallback')
        failures.append('ke-unavailable');run(ns('enz-peer-a','nft','delete','table','inet','enz_ke_failure'))
        run(['systemctl','stop','chronyd']);run(['date','-s','2038-01-01 00:00:00 UTC'],stdout=subprocess.DEVNULL);clock_changed=True
        before=udp_count();restart(normal);time.sleep(10)
        CHECK(not selected() and udp_count()==before,'bad clock bypassed TLS certificate validity')
        failures.append('bad-clock')
        run(['systemctl','stop','chronyd']);run(['date','-s','@'+str(int(saved+time.monotonic()-mono))],stdout=subprocess.DEVNULL);clock_changed=False
        restart(normal);wait(selected,'NTS recovery after manual clock/transport repair',90)
        return {'nts_authenticated':True,'fail_closed':failures,'plaintext_fallback':False,'external_server_availability_tested':False}
    finally:
        run(['systemctl','stop','chronyd'])
        if clock_changed:run(['date','-s','@'+str(int(saved+time.monotonic()-mono))],stdout=subprocess.DEVNULL)
        override.unlink(missing_ok=True);run(['systemctl','daemon-reload']);run(['systemctl','start','chronyd'])
        subprocess.run(['nft','delete','table','inet','enz_nts_probe'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stop(server)


def activation():
    active=('NetworkManager','systemd-resolved','firewalld','chronyd','apparmor')
    for service in active:CHECK(command_ok(['systemctl','is-active','--quiet',service]),'service not active: '+service)
    for service in ('systemd-networkd','systemd-timesyncd','dnsmasq'):
        CHECK(not command_ok(['systemctl','is-active','--quiet',service]),'competing/server role active: '+service)
    for timer in ('enzimos-home-history','enzimos-scrub','enzimos-trim'):
        CHECK(output(['systemctl','is-enabled',timer+'.timer'])=='enabled','timer not enabled: '+timer)
    CHECK(not command_ok(['systemctl','is-enabled','--quiet','enzimos-backup.timer']),'external backups default on')
    for timer in ('snapper-timeline.timer','fstrim.timer'):
        CHECK(not command_ok(['systemctl','is-enabled','--quiet',timer]),'competing default schedule enabled: '+timer)
    CHECK(backup.backup(automatic=True)['status']=='disabled-no-source-scan','disabled backup did work')
    disabled=Path('/var/lib/enzimos-control/home-history.disabled');disabled.touch()
    try:CHECK(backup.history(automatic=True)['status']=='disabled-no-source-scan','disabled history did work')
    finally:disabled.unlink()
    CHECK('discard=async' not in output(['findmnt','-n','-o','OPTIONS','/']),'continuous discard competes with weekly trim')
    CHECK('discards' in output(['cryptsetup','status','lab-root-crypt']),'LUKS discard pass-through not active')
    maintenance.maintain('scrub');maintenance.maintain('trim')
    return {'active':active,'backup_default_off':True,'disabled_work_suppressed':True,'owned_scrub_trim':True}


def mac_test():
    profiles=Path('/sys/kernel/security/apparmor/profiles').read_text()
    for name in ('enzimos-restic-backup','enzimos-restic-restore'):CHECK(name+' (enforce)' in profiles,'missing enforcing profile')
    if not os.path.ismount('/backup-repository'):run(['mount','/backup-repository'])
    c=backup.read_config()
    if not Path(c['repository'],'config').exists():backup.initialize()
    denied=subprocess.run(['aa-exec','-p','enzimos-restic-backup','--','restic','-r',c['repository'],'--password-file',c['password_file'],'--no-cache','backup','/etc/shadow'],capture_output=True,text=True,env=dict(os.environ,TMPDIR='/run/enzimos/restic-tmp'))
    CHECK(denied.returncode!=0,'backup profile read live shadow')
    deniednet=subprocess.Popen(['aa-exec','-p','enzimos-restic-backup','--','restic','-r','rest:http://10.203.1.1:19999','--password-file',c['password_file'],'--no-cache','snapshots'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    terminated=False
    try:deniednet.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        # Restic retries backend failures; termination is not itself denial proof.
        deniednet.terminate();terminated=True
        try:deniednet.communicate(timeout=5)
        except subprocess.TimeoutExpired:deniednet.kill();deniednet.communicate(timeout=5)
    CHECK(deniednet.returncode!=0,'file-only backup profile allowed network backend')
    journal=output(['journalctl','-k','--no-pager'])
    network=[line for line in journal.splitlines() if 'apparmor="DENIED"' in line and 'profile="enzimos-restic-backup"' in line and f'pid={deniednet.pid} ' in line and 'class="net"' in line]
    CHECK(network,'this process has no kernel-enforced network denial')
    CHECK(any('name="/etc/shadow"' in line and 'profile="enzimos-restic-backup"' in line and 'apparmor="DENIED"' in line for line in journal.splitlines()),'live shadow read denial was not observed')
    (BASE/'apparmor-denials.txt').write_text('\n'.join(x for x in journal.splitlines() if 'enzimos-restic-' in x))
    return {'enforcing_profiles':True,'live_shadow_denied':True,'network_denied':True,'retrying_network_probe_terminated':terminated,'positive_backup_restore':'covered by R2/R3, not inferred here'}


def run_all(case,check):
    global CHECK
    CHECK=check;BASE.mkdir(parents=True,exist_ok=True)
    # Freeze only TEST scheduling while deliberately changing the guest clock.
    timers=('enzimos-home-history.timer','enzimos-scrub.timer','enzimos-trim.timer','snapper-cleanup.timer','snapper-timeline.timer','shadow.timer')
    active_timers={timer:command_ok(['systemctl','is-active','--quiet',timer]) for timer in timers}
    for timer in timers:run(['systemctl','stop',timer])
    failures=[]
    def attempt(identifier,function):
        try:case(identifier,function)
        except Exception as exc:
            failures.append(identifier+': '+str(exc))
            print('ENZIMOS_SUBCASE_FAILED '+identifier+' '+str(exc),flush=True)
    try:
        attempt('S1',accounts)
        try:network_setup()
        except Exception as exc:failures.append('network setup: '+str(exc))
        else:
            attempt('S2',dns_test);attempt('S3',firewall_test);attempt('S4',nts_test)
        attempt('S5',activation);attempt('S6',mac_test)
        if failures:raise AssertionError('; '.join(failures))
    except BaseException:
        for p in sorted(BASE.iterdir())[:12]:
            if p.is_file() and p.suffix in ('.log','.txt'):
                print('ENZIMOS_DEFAULTS_DIAGNOSTIC '+p.name+'\n'+p.read_text(errors='replace')[-16000:],flush=True)
        result=subprocess.run(['journalctl','-b','--no-pager','-n','80','-g','polkit|pam_|chrony|DENIED|dnsmasq'],capture_output=True,text=True)
        print(result.stdout[-24000:],flush=True)
        raise
    finally:
        for p,log in reversed(PROCESSES):stop(p);log.close()
        for letter in ('a','b'):
            subprocess.run(['nmcli','connection','delete','enz-net-'+letter],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['ip','netns','delete','enz-peer-'+letter],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for timer in timers:
            if active_timers[timer]:run(['systemctl','start',timer])
