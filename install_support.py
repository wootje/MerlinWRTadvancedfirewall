#!/usr/bin/env python3
"""Native UI/hook installation; no network downloads and no firmware modifications."""
from pathlib import Path
import os, re, shutil, sys, time
import guard
MARK = '# MCG-ADDON'
TITLE = '<title>MerlinWRT Advanced Firewall</title>'
OLD_TITLE = '<title>Merlin Country Guard</title>'
HOOKS = {
 'firewall-start': '/jffs/scripts/mcg boot >/tmp/mcg-boot.log 2>&1 ' + MARK,
 'services-start': '/jffs/scripts/mcg startup >/tmp/mcg-startup.log 2>&1 ' + MARK,
 'service-event': 'case "$1:$2" in start:MCG_*) /jffs/scripts/mcg web "${2#MCG_}" >/tmp/mcg-web.log 2>&1 & ;; esac ' + MARK,
}

def patch_hook(text, line=None):
    if text and not re.match(r'^#![^\n]*(?:/sh|/ash|/bash)(?:\s|$)', text):
        raise guard.GuardError('An existing hook has no recognized shell shebang; it was not modified.')
    lines = [x for x in (text or '#!/bin/sh\n').splitlines() if MARK not in x]
    if line:
        # Preserve other add-ons and a conventional final exit.
        pos = len(lines)
        while pos and not lines[pos-1].strip(): pos -= 1
        if pos and re.fullmatch(r'\s*exit(?:\s+[0-9]+)?\s*', lines[pos-1]): pos -= 1
        lines.insert(pos, line)
    return '\n'.join(lines) + '\n'

def hooks(install=True):
    root=Path('/jffs/scripts'); root.mkdir(parents=True,exist_ok=True)
    # Validate all three before modifying any.
    changes=[]
    for name,line in HOOKS.items():
        p=root/name
        if p.is_symlink(): raise guard.GuardError('Symlink hook was not modified: '+str(p))
        old=p.read_text() if p.exists() else ''
        changes.append((p,patch_hook(old,line if install else None)))
    backup=guard.DATA/'install-backups'/time.strftime('%Y%m%d-%H%M%S')
    backup.mkdir(parents=True,exist_ok=True); os.chmod(backup,0o700)
    for p,new in changes:
        if p.exists(): shutil.copy2(p,backup/p.name)
        if install or p.exists(): guard.atomic(p,new,0o755)

def maintenance_cron(install=True):
    from tools import maintenance
    import updater
    guard.command(['cru', 'd', 'MCG_Updates'], check=False)
    guard.command(['cru', 'd', 'MCG_Maintenance'], check=False)
    prefs = updater.settings()
    needed = maintenance.settings()['auto_update'] or (prefs['enabled'] and prefs['auto_check'])
    if install and needed:
        guard.command(['cru', 'a', 'MCG_Maintenance', '*/5 * * * * /jffs/scripts/mcg maintenance >/tmp/mcg-maintenance.log 2>&1'])


def cron(install=True):
    for name, rule in (
       ('MCG_Tick', '* * * * * /jffs/scripts/mcg tick >/tmp/mcg-tick.log 2>&1'),
       ('MCG_Mirror', '23 * * * * /jffs/scripts/mcg mirror >/tmp/mcg-mirror.log 2>&1'),
       ('MCG_Feeds', '43 4 * * * /jffs/scripts/mcg refresh >/tmp/mcg-refresh.log 2>&1')):
        guard.command(['cru', 'd', name], check=False)
        if install: guard.command(['cru', 'a', name, rule])
    maintenance_cron(install)

def menu(page=None):
    native=Path('/www/require/modules/menuTree.js'); tmp=Path('/tmp/menuTree.js')
    if not native.is_file():
        raise guard.GuardError('Native menuTree.js is missing; open the reported user page directly.')
    old=tmp.read_text() if tmp.exists() else native.read_text()
    lines=[s for s in old.splitlines() if '// MCG-ADDON' not in s]
    if page:
        target=next((i for i,l in enumerate(lines) if re.search(r'url:\s*"Advanced_Firewall_Content.asp",\s*tabName:',l)),None)
        if target is None:
            raise guard.GuardError('The Firewall tab position was not recognized; the existing menu was not modified.')
        lines.insert(target+1, '{url: "'+page+'", tabName: "Advanced Firewall"}, // MCG-ADDON')
    # Same shared temporary menu mechanism as native Merlin add-ons. Only our marker changes.
    guard.atomic(tmp,'\n'.join(lines)+'\n',0o644)
    guard.command(['umount',str(native)],check=False)
    guard.command(['mount','-o','bind',str(tmp),str(native)])

def mount_ui(remove=False):
    root=Path('/www/user'); root.mkdir(parents=True,exist_ok=True)
    owned=[]; free=[]
    for i in range(1,21):
        p=root/('user'+str(i)+'.asp')
        if p.exists():
            if any(t in p.read_text(errors='replace')[:3000] for t in (TITLE, OLD_TITLE)): owned.append(p)
        elif not p.is_symlink(): free.append(p)
        elif str(p.resolve(strict=False)) == str(guard.APP/'web/guard.asp'): owned.append(p)
    assets=root/'mcg'
    if remove:
        for p in owned:
            p.unlink(missing_ok=True); p.with_suffix('.title').unlink(missing_ok=True)
        if assets.is_dir():
            for name in ('guard.js','guard.css','countries.json','status.json','result.json','iptables.txt'):
                p=assets/name
                if p.is_symlink(): p.unlink()
            try: assets.rmdir()
            except OSError: pass
        menu(None)
        return
    if not owned and not free: raise guard.GuardError('No free native user1..20 page is available.')
    p=(owned or free)[0]
    if p.exists() or p.is_symlink(): p.unlink()
    p.symlink_to(guard.APP/'web/guard.asp')
    assets.mkdir(exist_ok=True)
    mapping={'guard.js':guard.APP/'web/guard.js','guard.css':guard.APP/'web/guard.css','countries.json':guard.APP/'countries.json'}
    for name in ('status.json','result.json','iptables.txt'): mapping[name]=guard.PUBLIC/name
    for name,target in mapping.items():
        link=assets/name
        if link.exists() and not link.is_symlink(): raise guard.GuardError('An asset already exists and is not an owned symlink: '+str(link))
        link.unlink(missing_ok=True); link.symlink_to(target)
    guard.atomic(guard.DATA/'page.txt',p.name+'\n')
    try: menu(p.name)
    except guard.GuardError as e:
        print('MENU WARNING: '+str(e),file=sys.stderr)
    print('Web page: /'+p.name+' (on the same HTTPS address and port as router administration)')

def main():
    if os.geteuid()!=0: raise guard.GuardError('Root is required.')
    action=sys.argv[1] if len(sys.argv)>1 else 'mount'
    guard.setup()
    with guard.locked(wait=True):
        if action=='install': hooks(); cron(); mount_ui()
        elif action=='startup': cron(); mount_ui()
        elif action=='mount': mount_ui()
        elif action=='uninstall':
            hooks(False); cron(False)
            try: mount_ui(True)
            except guard.GuardError as e: print(str(e),file=sys.stderr)
        else: raise guard.GuardError('Unknown installation action.')

if __name__=='__main__':
    try: main()
    except Exception as e: print('INSTALL ERROR: '+str(e),file=sys.stderr);sys.exit(1)
