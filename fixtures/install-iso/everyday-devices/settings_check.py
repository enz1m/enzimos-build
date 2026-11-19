# SPDX-License-Identifier: MIT
"""Manual native Settings against real disposable IPP/CUPS/polkit providers."""
import json
from pathlib import Path
import check as b
HOME=Path('/home/admin')
def phase(label):print('ENZIMOS_PRINTER_SETTINGS_'+label,flush=True)
def wait(check,seconds=1200):b.wait(check,seconds)
def ack(name):wait(lambda:(HOME/('printer-'+name)).is_file())
def queues():
 p=b.run(['lpstat','-p'],ok=False)
 return [line.split()[1] for line in p.stdout.splitlines() if line.startswith('printer ')]
def pending(user=None):
 args=['lpstat','-W','not-completed']+(['-u',user] if user else ['-o'])
 return {line.split()[0] for line in b.run(args,ok=False).stdout.splitlines() if line.split()}
try:
 b.LAB.mkdir(mode=0o755);b.foundation()
 assert not queues(),'fixture requires no pre-existing queues'
 spool=b.LAB/'printer';spool.mkdir()
 b.start(['ippeveprinter','-p','8631','-f','application/pdf','-d',str(spool),'-k','enzimOS Native Test Printer'],'printer')
 wait(lambda:':8631 ' in b.run(['ss','-ltn']).stdout,30)
 discovery=b.run(['ippfind','-T','4','_ipp._tcp','--print'],timeout=15,ok=False)
 assert ':8631/' in discovery.stdout
 phase('READY normal PAM/Settings Printers/Search/Add/Cancel; then native Terminal touch /home/admin/printer-denial-reviewed')
 ack('denial-reviewed');assert not queues()
 phase('DENIAL_PASS now native Add/admin approval')
 wait(lambda:len(queues())==1)
 queue=queues()[0];assert queue.isascii() and all(c.isalnum() or c in '-_' for c in queue)
 details=b.run(['lpoptions','-p',queue]).stdout
 print('ENZIMOS_PRINTER_FIXTURE_OPTIONS '+details,flush=True)
 sharing=b.run(['ipptool','-tv','ipp://localhost:631/printers/'+queue,'/run/enzimos-testpayload/sharing.test']).stdout
 print('ENZIMOS_PRINTER_SHARING_IPP '+sharing,flush=True)
 phase('ADD_PASS native Pause queue; then Test page while paused')
 wait(lambda:'disabled' in b.run(['lpstat','-p',queue]).stdout)
 page=Path('/usr/share/cups/data/default-testpage.pdf')
 if not page.is_file():page=Path('/usr/share/cups/data/testprint')
 assert page.is_file()
 b.run(['lp','-d',queue,'-t','Private fixture job',str(page)])
 wait(lambda:len(pending('root'))==1,10);rootid=next(iter(pending('root')))
 phase('PAUSE_PASS Root dummy job queued; native Test page and review only your job then touch /home/admin/printer-privacy-reviewed')
 wait(lambda:len(pending('admin'))==1)
 adminid=next(iter(pending('admin')));assert adminid!=rootid
 ack('privacy-reviewed')
 phase('PRIVACY_REVIEWED native Cancel your job without admin prompt')
 wait(lambda:not pending('admin'));assert rootid in pending('root')
 b.run(['cancel',rootid]);assert not pending()
 phase('CANCEL_PASS now native Resume then Remove')
 wait(lambda:'disabled' not in b.run(['lpstat','-p',queue],ok=False).stdout and queues()==[queue])
 phase('RESUME_PASS native Remove queue; review final empty list then touch /home/admin/printer-final-reviewed')
 wait(lambda:not queues());ack('final-reviewed')
 result={'schema':1,'status':'PASS','source21_private_overlay':True,'real_ipp_discovery':True,'native_polkit_denied_then_approved':True,'owner_only_job_review':True,'own_job_cancel_preserved_root_job':True,'native_pause_resume_remove':True,'physical_printer_qualified':False,'default_image_qualified':False}
 Path('/var/tmp/printer-settings-native-result.json').write_text(json.dumps(result)+'\n')
 phase('NATIVE_PASS')
finally:b.cleanup()
