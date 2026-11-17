"""Own QEMU guest, real PAM/audit events, then bounded normal-only capture.

The controller disconnects this container's network before collection. Keys
live in this container's tmpfs only. No host SSH/audit configuration changes.
"""
import argparse
import base64
import hashlib
import json
import socket
import subprocess
import time
from pathlib import Path


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf8')


def command(argv,timeout=60):
    return subprocess.run(argv,capture_output=True,timeout=timeout,check=False)


def response(body):
    lines=[line.strip() for line in body.decode('utf8').splitlines() if line.strip().startswith('{')]
    if len(lines)!=1:raise RuntimeError('owned_guest_json_response')
    return json.loads(lines[0])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--owner',required=True);args=parser.parse_args()
    owner=args.owner
    if not owner.startswith('zt-native-audit-v113-') or len(owner)>64:raise RuntimeError('guest_owner')
    out=Path('/runtime');source=Path('/recipe');keys=Path('/tmp/native-audit-keys');keys.mkdir(mode=0o700)
    public={}
    for name in ('operator','control'):
        key=keys/name;r=command(['ssh-keygen','-q','-t','ed25519','-N','','-C',owner+'-'+name,'-f',str(key)])
        if r.returncode:raise RuntimeError('guest_ssh_key_generation')
        public[name]=key.with_suffix('.pub').read_text().strip()
    policy='zt-normal ALL=(root) NOPASSWD: /usr/bin/tail /var/log/syslog\n'
    contents={'/usr/local/libexec/zt-native-audit-control':(source/'guest_control.py').read_text(),
        '/usr/local/bin/zt-normal-log-read':(source/'normal_operation.py').read_text(),
        '/etc/sudoers.d/zt-normal-audit':policy,
        '/etc/ssh/sshd_config.d/91-zt-native-audit.conf':
            'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nUsePAM yes\nPrintMotd no\nPrintLastLog no\n',
        '/etc/cloud/cloud.cfg.d/99-zt-datasource.cfg':'datasource_list: [NoCloud]\n'}
    users=[{'name':'zt-normal','lock_passwd':True,'shell':'/bin/bash','ssh_authorized_keys':[
        'restrict,pty,command="/usr/local/bin/zt-normal-log-read" '+public['operator']]},
        {'name':'root','ssh_authorized_keys':[
            'restrict,command="/usr/local/libexec/zt-native-audit-control" '+public['control']]}]
    config={'users':users,'disable_root':False,'ssh_pwauth':False,'timezone':'UTC','package_update':True,
        'packages':['auditd','openssh-server','rsyslog','sudo'],
        'write_files':[{'path':path,'owner':'root:root','permissions':'0440' if 'sudoers.d/' in path else
            '0755' if path.startswith('/usr/local/') else '0644','content':text} for path,text in contents.items()],
        'runcmd':[['/usr/sbin/visudo','-cf','/etc/sudoers.d/zt-normal-audit'],
            ['/bin/systemctl','enable','--now','auditd'],['/bin/systemctl','enable','--now','rsyslog'],
            ['/usr/sbin/auditctl','-b','8192'],
            ['/bin/systemctl','restart','ssh'],['/bin/timedatectl','set-ntp','false'],
            ['/usr/bin/mkdir','-p','/var/lib/zt-native-audit'],['/usr/bin/touch','/var/lib/zt-native-audit/ready']]}
    (out/'user-data').write_text('#cloud-config\n'+json.dumps(config,indent=2)+'\n')
    (out/'meta-data').write_text(json.dumps({'instance-id':owner,'local-hostname':'zt-native-normal'}))
    write(out/'collection-plan.json',{'owner':owner,'role':'controlled_normal_training','sessions_requested':8,
        'normal_command':['/usr/bin/tail','/var/log/syslog'],'policy_sha256':hashlib.sha256(policy.encode()).hexdigest(),
        'synthetic_audit_records_written_by_scripts':False,'training_only':True,'goal_qualified':False,
        'new_independent_evaluation':False,'keys_persisted_outside_tmpfs':False,
        'host_configuration_changed':False,'aws_calls':0,'paid_api_calls':0})
    r=command(['cloud-localds',str(out/'seed.img'),str(out/'user-data'),str(out/'meta-data')])
    if r.returncode:raise RuntimeError('guest_seed_creation')
    r=command(['qemu-img','create','-f','qcow2','-F','qcow2','-b','/image/guest.img',str(out/'owned-overlay.qcow2'),'6G'])
    if r.returncode:raise RuntimeError('guest_overlay_creation')
    sshbase=['ssh','-F','/dev/null','-p','2222','-o','BatchMode=yes','-o','ConnectTimeout=5',
        '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile=/tmp/zt-native-known-hosts',
        '-o','LogLevel=ERROR','-o','IdentitiesOnly=yes']
    def control(action,timeout=30):
        return command([*sshbase,'-i',str(keys/'control'),'root@127.0.0.1',action],timeout)
    log=(out/'qemu.log').open('wb');process=None
    report={'completed':False,'owner':owner,'role':'controlled_normal_training','goal_qualified':False,
        'aws_calls':0,'paid_api_calls':0,'host_configuration_changed':False,'sessions':[]}
    try:
        process=subprocess.Popen(['qemu-system-x86_64','-machine','q35,accel=tcg','-cpu','max','-smp','2','-m','1536',
            '-drive','file=/runtime/owned-overlay.qcow2,format=qcow2,if=virtio',
            '-drive','file=/runtime/seed.img,format=raw,media=cdrom,readonly=on',
            '-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22','-device','virtio-net-pci,netdev=net0',
            '-display','none','-serial','file:/runtime/serial.log','-monitor','none','-no-reboot'],
            stdout=log,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+1200;last=None
        while time.monotonic()<deadline:
            if process.poll() is not None:raise RuntimeError('owned_guest_exited_during_boot')
            try:r=control('status',20)
            except subprocess.TimeoutExpired:r=None
            if r is not None and r.returncode==0:
                status=response(r.stdout)
                if status['ready'] and status['audit']['enabled'] in {'1','2'}:break
            if last is None or time.monotonic()-last>=30:
                print(json.dumps({'phase':'guest_boot_or_provision','owner':owner}),flush=True);last=time.monotonic()
            time.sleep(2)
        else:raise RuntimeError('owned_guest_provision_timeout')
        report['guest_before_isolation']=status
        write(out/'provision-ready.json',{'owner':owner,'guest':status,'ready':True})
        print(json.dumps({'phase':'ready_for_network_disconnect','owner':owner}),flush=True)
        deadline=time.monotonic()+180
        while not (out/'network-disconnected.json').exists():
            if time.monotonic()>deadline:raise RuntimeError('owned_guest_network_isolation_timeout')
            time.sleep(.5)
        isolation=json.loads((out/'network-disconnected.json').read_bytes())
        if isolation['owner']!=owner or isolation['networks']!={}:raise RuntimeError('owned_guest_network_isolation_receipt')
        if {name for _,name in socket.if_nameindex()}!={'lo'}:raise RuntimeError('owned_container_interface_not_loopback')
        report['outer_networks_after_disconnect']={};report['outer_interfaces']=['lo']
        r=control('begin');(out/'begin.log').write_bytes(r.stdout+b'\n'+r.stderr)
        if r.returncode:raise RuntimeError('owned_guest_collection_begin')
        begun=response(r.stdout);report['guest_collection_begin']=begun
        if begun['status']['policy_sha256']!=hashlib.sha256(policy.encode()).hexdigest():raise RuntimeError('guest_policy_drift')
        for number in range(1,9):
            r=command([*sshbase,'-tt','-i',str(keys/'operator'),'zt-normal@127.0.0.1','owned-normal-log-read'],60)
            (out/f'session-{number}.stdout').write_bytes(r.stdout);(out/f'session-{number}.stderr').write_bytes(r.stderr)
            receipt={'number':number,'ssh_exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest()}
            if r.returncode==0:
                receipt['operation']=response(r.stdout)
            report['sessions'].append(receipt);write(out/'partial.json',report)
            print(json.dumps({'phase':'real_ssh_sudo_session','number':number,'exit_code':r.returncode}),flush=True)
            if r.returncode:raise RuntimeError('owned_normal_session_failed')
        time.sleep(1)
        r=control('capture',60)
        if r.returncode:raise RuntimeError('owned_guest_audit_capture')
        snapshot=response(r.stdout);body=base64.b64decode(snapshot.pop('audit_base64'),validate=True)
        if len(body)!=snapshot['bytes'] or hashlib.sha256(body).hexdigest()!=snapshot['sha256']:
            raise RuntimeError('owned_guest_capture_pin')
        (out/'audit-native.source').write_bytes(body);write(out/'capture.json',snapshot)
        if snapshot['status']['audit']['lost']!='0':raise RuntimeError('owned_guest_audit_events_lost')
        report['capture']=snapshot;report['completed']=True
    finally:
        if process is not None and process.poll() is None:
            try:control('poweroff',10);process.wait(timeout=30)
            except (subprocess.TimeoutExpired,OSError):
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
        report['owned_qemu_exited']=process is not None and process.poll() is not None
        log.close();write(out/'guest-run.json',report)
    if not report['completed'] or not report['owned_qemu_exited']:raise RuntimeError('owned_guest_capture_incomplete')
    print(json.dumps({'completed':True,'sessions':len(report['sessions']),'native_audit_bytes':report['capture']['bytes']}),flush=True)


if __name__=='__main__':main()
