"""Offline regression tests for installer, schedules, source refresh and telemetry.

No real router commands, packet filtering, remote downloads or live updates occur.
"""
from pathlib import Path
import copy
import hashlib
import json
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard as g
import updater as u
import install_support as integration
from tools import maintenance as m, telemetry as t, bootstrap as b
ROOT = Path(__file__).resolve().parents[1]
SHA = 'a' * 40


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(g, 'DATA', self.root/'data'), patch.object(g, 'RUN', self.root/'run'),
                        patch.object(g, 'PUBLIC', self.root/'run/public'),
                        patch.object(u, 'INSTALL_APP', self.root/'app'),
                        patch.object(u, 'resource_check'), patch.object(m, 'reconcile_schedule')]
        for p in self.patches: p.start()
        g.setup()
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()
    def saved(self, enabled=True):
        config = g.validate_config(dict(g.DEFAULT, enabled=enabled, country_enabled=True, countries=['NL']))
        bundle = {'geo':['8.8.8.0/24'], 'skynet':['9.9.9.9/32'], 'abuse':[],
                  'meta': {'NL':{'entries':1, 'fetched':1}, 'skynet':{'entries':1}}, 'created':1}
        saved = {'config': config, 'bundle':bundle, 'confirmed':1}
        active = {'config':config, 'bundle':bundle, 'gen':'MCG000001', 'started':1}
        g.save_json(g.DATA/'confirmed.json',saved)
        if enabled: g.save_json(g.RUN/'active.json',active)
        return saved, active
    def geo(self, changed=False):
        return {'geo':['8.8.8.0/25' if changed else '8.8.8.0/24'],
                'meta': {'NL':{'entries':1,'fetched':2,'checked':3,'commit':SHA}}}


class ScheduleTests(Sandbox):
    def test_upgrade_two_field_preferences(self):
        g.save_json(g.DATA/'update-settings.json', {'auto_check':False,'auto_download':False})
        self.assertEqual(u.settings(), dict(u.DEFAULT_SETTINGS,auto_check=False,auto_download=False))
    def test_save_preserves_legacy_file_shape(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS, interval_hours=6))
        self.assertEqual(set(g.read_json(g.DATA/'update-settings.json')), {'auto_check','auto_download'})
        self.assertEqual(u.settings()['interval_hours'],6)
    def test_global_disable_stops_manual_check(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS, enabled=False))
        with patch.object(g,'fetch') as fetch, self.assertRaisesRegex(g.GuardError,'disabled'):
            u.check()
        fetch.assert_not_called()
    def test_global_disable_stops_manual_download(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        with patch.object(g,'fetch') as fetch, self.assertRaises(g.GuardError): u.download_latest()
        fetch.assert_not_called()
    def test_global_disable_stops_install(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        with patch.object(u,'install_tree') as install, self.assertRaises(g.GuardError): u.install_staged(SHA)
        install.assert_not_called()
    def test_global_disable_stops_scheduled_network(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        with patch.object(g,'fetch') as fetch: u.check(scheduled=True)
        fetch.assert_not_called()
    def test_global_disable_mirrors_to_legacy_auto_preferences(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        self.assertEqual(g.read_json(g.DATA/'update-settings.json'),{'auto_check':False,'auto_download':False})
    def test_manual_only_allows_explicit_check(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,auto_check=False,auto_download=False))
        g.save_json(g.DATA/'installed.json',{'commit':SHA})
        with patch.object(g,'fetch',return_value=(json.dumps({'sha':SHA}),'')) as fetch:
            u.check()
        self.assertEqual(fetch.call_count,1)
    def test_six_hour_schedule_is_not_daily(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,interval_hours=6,auto_download=False))
        g.save_json(g.DATA/'installed.json',{'commit':SHA})
        g.save_json(g.DATA/'update-state.json',{'last_attempt':time.time()-7*3600})
        with patch.object(g,'fetch',return_value=(json.dumps({'sha':SHA}),'')) as fetch: u.check(scheduled=True)
        fetch.assert_called_once()
    def test_six_hour_schedule_waits_when_not_due(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,interval_hours=6))
        g.save_json(g.DATA/'update-state.json',{'last_attempt':time.time()-5*3600})
        with patch.object(g,'fetch') as fetch: u.check(scheduled=True)
        fetch.assert_not_called()
    def test_invalid_github_intervals(self):
        for interval in (0,721,-1,True,1.5,'24'):
            with self.subTest(interval=interval), self.assertRaises(g.GuardError):
                u.save_settings(dict(u.DEFAULT_SETTINGS,interval_hours=interval))
    def test_valid_custom_github_interval(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,interval_hours=17))
        self.assertEqual(u.settings()['interval_hours'],17)
    def test_invalid_country_preferences(self):
        for value in ({'auto_update':True,'interval_hours':0},{'auto_update':True,'interval_hours':721},
                      {'auto_update':'yes','interval_hours':24},{'auto_update':True,'interval_hours':True},
                      {'auto_update':True,'interval_hours':1.5},{'auto_update':True}):
            with self.subTest(value=value),self.assertRaises(g.GuardError): m.save_settings(value)
    def test_country_schedule_independent_of_github(self):
        m.save_settings({'auto_update':True,'interval_hours':5})
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        self.assertEqual(m.settings(),{'auto_update':True,'interval_hours':5})
        self.assertIsNone(u.status()['next_check'])
        self.assertIsNotNone(m.status()['next_check'])
    def test_country_manual_still_works_when_automatic_disabled(self):
        self.saved(False)
        m.save_settings({'auto_update':False,'interval_hours':24})
        with patch.object(g,'country_bundle',return_value=self.geo()) as sources: m.refresh_countries()
        sources.assert_called_once_with(['NL'],refresh=True)
    def test_disabled_country_schedule_no_network(self):
        m.save_settings({'auto_update':False,'interval_hours':24})
        with patch.object(g,'country_bundle') as sources: m.refresh_countries(scheduled=True)
        sources.assert_not_called()
    def test_country_not_due_no_fetch(self):
        self.saved(False)
        g.save_json(g.DATA/'country-update-state.json',{'last_attempt':time.time()})
        with patch.object(g,'country_bundle') as sources: m.refresh_countries(scheduled=True)
        sources.assert_not_called()
    def test_due_country_interval_honored(self):
        self.saved(False)
        m.save_settings({'auto_update':True,'interval_hours':3})
        g.save_json(g.DATA/'country-update-state.json',{'last_attempt':time.time()-4*3600})
        with patch.object(g,'country_bundle',return_value=self.geo()) as sources: m.refresh_countries(scheduled=True)
        sources.assert_called_once()
    def test_empty_country_schedule_no_download(self):
        with patch.object(g,'country_bundle') as sources: m.refresh_countries(scheduled=True)
        sources.assert_not_called()
    def test_empty_country_manual_errors(self):
        with self.assertRaises(g.GuardError): m.refresh_countries([])
    def test_country_cron_failure_restores_setting(self):
        m.reconcile_schedule.side_effect=g.GuardError('cron failure')
        with self.assertRaises(g.GuardError): m.save_settings({'auto_update':False,'interval_hours':9})
        self.assertEqual(m.settings(),m.DEFAULT_SETTINGS)
    def test_updater_cron_failure_restores_settings(self):
        m.reconcile_schedule.side_effect=g.GuardError('cron failure')
        with self.assertRaises(g.GuardError): u.save_settings(dict(u.DEFAULT_SETTINGS,interval_hours=9))
        self.assertEqual(u.settings(),u.DEFAULT_SETTINGS)
    def test_both_disabled_remove_maintenance_cron(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        m.save_settings({'auto_update':False,'interval_hours':24})
        with patch.object(g,'command') as cmd: integration.maintenance_cron()
        self.assertFalse(any(call.args[0][:2]==['cru','a'] for call in cmd.call_args_list))
    def test_country_only_schedule_installed(self):
        u.save_settings(dict(u.DEFAULT_SETTINGS,enabled=False))
        with patch.object(g,'command') as cmd: integration.maintenance_cron()
        adds=[call.args[0] for call in cmd.call_args_list if call.args[0][:2]==['cru','a']]
        self.assertEqual(len(adds),1)
        self.assertIn('*/5',adds[0][-1])
    def test_scheduler_runs_github_after_country_error(self):
        with patch.object(m,'refresh_countries',side_effect=g.GuardError('bad feed')),patch.object(u,'check',return_value={'message':'ok'}) as check:
            result=m.run_scheduled()
        self.assertFalse(result['jobs']['countries']['ok']);self.assertTrue(result['jobs']['github']['ok'])
        check.assert_called_once_with(scheduled=True)
    def test_status_endpoints_never_fetch(self):
        with patch.object(g,'fetch') as fetch:
            m.status();u.status();t.attach({})
        fetch.assert_not_called()


class CountryRefreshTests(Sandbox):
    def test_draft_choices_do_not_change_active_selection(self):
        saved,active=self.saved()
        with patch.object(g,'country_bundle',return_value=self.geo()) as fetch,patch.object(m,'apply_bundle') as apply:
            m.refresh_countries(['DE'])
        apply.assert_not_called()
        self.assertEqual(g.read_json(g.DATA/'confirmed.json'),saved)
    def test_download_failure_retains_active_policy(self):
        saved,active=self.saved()
        with patch.object(g,'country_bundle',side_effect=g.GuardError('partial source failure')),patch.object(g,'build_generation') as build:
            with self.assertRaises(g.GuardError): m.refresh_countries()
        build.assert_not_called();self.assertEqual(g.read_json(g.RUN/'active.json'),active)
        self.assertEqual(g.read_json(g.DATA/'confirmed.json'),saved)
        self.assertIn('partial',m.status()['error'])
    def test_unchanged_networks_keep_generation(self):
        saved,active=self.saved()
        with patch.object(g,'doctor',return_value={'ready':True}),patch.object(g,'build_generation') as build:
            changed=m.apply_bundle(saved,self.geo())
        self.assertFalse(changed);build.assert_not_called()
        self.assertEqual(g.read_json(g.RUN/'active.json')['gen'],active['gen'])
    def test_country_refresh_keeps_reputation_and_ports(self):
        saved,active=self.saved()
        with patch.object(g,'doctor',return_value={'ready':True}): m.apply_bundle(saved,self.geo())
        result=g.read_json(g.DATA/'confirmed.json')
        self.assertEqual(result['bundle']['skynet'],saved['bundle']['skynet'])
        self.assertEqual(result['config'],saved['config'])
    def test_failed_kernel_switch_attempts_previous_generation(self):
        saved,active=self.saved()
        new=dict(active,gen='MCG000002')
        with patch.object(g,'doctor',return_value={'ready':True}),patch.object(g,'build_generation',return_value=new),patch.object(g,'switch_generation',side_effect=[g.GuardError('switch failed'),None]) as switch,patch.object(g,'cleanup_generation') as cleanup:
            with self.assertRaises(g.GuardError): m.apply_bundle(saved,self.geo(True))
        self.assertEqual(switch.call_args_list[-1].args[0],active)
        cleanup.assert_called_with('MCG000002')
    def test_unknown_acceleration_refuses_live_replacement(self):
        saved,_=self.saved()
        with patch.object(g,'doctor',return_value={'ready':False,'warnings':['unknown acceleration']}),patch.object(g,'build_generation') as build:
            with self.assertRaises(g.GuardError): m.apply_bundle(saved,self.geo(True))
        build.assert_not_called()
    def test_same_commit_country_file_is_reused(self):
        idx={'commit':SHA,'fetched':100,'paths':{'NL':'CIDR/Netherlands/Netherlands-ipv4-Hackers.Zone.txt'}}
        g.save_json(g.DATA/'cache/country-NL.json',{'commit':SHA,'fetched':10,'entries':['8.8.8.0/24']})
        with patch.object(g,'country_index',return_value=idx) as index,patch.object(g,'fetch') as fetch:
            result=g.country_bundle(['NL'],refresh=True)
        index.assert_called_once_with(force=True);fetch.assert_not_called()
        self.assertEqual(result['meta']['NL']['checked'],100)
    def test_missing_country_path_is_not_silently_ignored(self):
        with patch.object(g,'country_index',return_value={'commit':SHA,'fetched':100,'paths':{}}):
            with self.assertRaises(g.GuardError): g.country_bundle(['NL'],refresh=True)


class TelemetryTests(Sandbox):
    def row(self, **kwargs):
        return dict(source='10.10.10.10',destination='8.8.8.8',protocol='tcp',state='ESTABLISHED',sport=12345,dport=443,bytes=200,**kwargs)
    def test_valid_statistics_ranges(self):
        t.save_settings({'interval_minutes':5,'retention_hours':168,'top_n':50})
        self.assertEqual(t.settings()['interval_minutes'],5)
    def test_invalid_statistics_ranges(self):
        for key,value in (('interval_minutes',0),('interval_minutes',61),('retention_hours',169),('top_n',51),('interval_minutes',True)):
            with self.subTest(key=key,value=value),self.assertRaises(g.GuardError): t.save_settings(dict(t.DEFAULT_SETTINGS,**{key:value}))
    def test_private_ranges(self):
        for value in ('10.0.0.1','172.16.0.1','172.31.255.254','192.168.1.1','169.254.1.2'): self.assertTrue(t.local_ip(value))
        for value in ('172.15.255.1','172.32.0.1','8.8.8.8',None,'invalid'): self.assertFalse(t.local_ip(value))
    def test_outbound_endpoint_mapping(self):
        self.assertEqual(t.endpoints(self.row()),('10.10.10.10','8.8.8.8','out'))
    def test_inbound_dnat_mapping(self):
        row=self.row();row.update(source='1.1.1.1',destination='8.8.8.8',reply_source='10.10.10.20')
        self.assertEqual(t.endpoints(row),('10.10.10.20','1.1.1.1','in'))
    def test_rankings_account_for_missing_bytes(self):
        row=self.row();row['bytes']=None
        result=t.summarize([self.row(),row],20)
        self.assertEqual(result['local_ips'][0]['connections'],2)
        self.assertEqual(result['local_ips'][0]['accounted_rows'],1)
        self.assertEqual(result['local_ips'][0]['known_bytes'],200)
    def test_top_n_is_bounded(self):
        rows=[]
        for i in range(30):
            row=self.row();row['source']='10.10.10.'+str(i+1);rows.append(row)
        self.assertEqual(len(t.summarize(rows,5)['local_ips']),5)
    def test_cpu_percent_uses_sample_difference(self):
        self.assertEqual(t.cpu_percent({'total':200,'idle':110},{'total':100,'idle':50}),40)
    def test_cpu_reset_is_unknown(self):
        self.assertIsNone(t.cpu_percent({'total':50,'idle':10},{'total':100,'idle':50}))
        self.assertIsNone(t.cpu_percent({'total':100,'idle':10},None))
    def test_interface_rates_bits_per_second(self):
        values=t.interface_rates({'eth0':{'rx':2000,'tx':1000}},{'eth0':{'rx':1000,'tx':500}},True,10)
        self.assertEqual(values['eth0']['rx_bps'],800)
        self.assertEqual(values['eth0']['tx_bps'],400)
    def test_interface_reset_is_unknown_not_negative(self):
        values=t.interface_rates({'eth0':{'rx':20,'tx':10}},{'eth0':{'rx':1000,'tx':500}},True,10)
        self.assertIsNone(values['eth0']['rx_bps'])
    def test_interfaces_not_summed(self):
        current={'eth0':{'rx':100,'tx':100},'br0':{'rx':100,'tx':100}}
        values=t.interface_rates(current,current,True,10)
        self.assertEqual(set(values),{'eth0','br0'})
    def test_rule_protocol_variants_grouped(self):
        rows=[dict(direction='out',reason='port1',target='DROP',packets=1,bytes=10)]*2
        self.assertEqual(t.rule_totals(rows)['out:port1:DROP'],{'packets':2,'bytes':20})
    def test_rule_generation_change_creates_gap(self):
        current={'in:country:DROP':{'packets':20,'bytes':200}}
        previous={'in:country:DROP':{'packets':10,'bytes':100}}
        self.assertIsNone(t.rule_deltas(current,previous,False,60)[0]['packets'])
    def test_rule_delta_rate(self):
        current={'in:country:DROP':{'packets':30,'bytes':300}}
        previous={'in:country:DROP':{'packets':10,'bytes':100}}
        self.assertEqual(t.rule_deltas(current,previous,True,10)[0]['pps'],2)
    def test_rule_external_counter_reset_creates_gap(self):
        current={'in:country:DROP':{'packets':1,'bytes':10}}
        previous={'in:country:DROP':{'packets':10,'bytes':100}}
        self.assertIsNone(t.rule_deltas(current,previous,True,10)[0]['pps'])
    def test_retention_expires_old_points(self):
        now=time.time()
        out=t.keep_history([{'at':now-90000},{'at':now}],now,t.DEFAULT_SETTINGS)
        self.assertEqual(len(out),1)
    def test_history_has_absolute_row_cap(self):
        now=time.time()
        self.assertEqual(len(t.keep_history([{'at':now}]*10100,now,dict(t.DEFAULT_SETTINGS,retention_hours=168))),10080)
    def state(self):
        return {'doctor':{'memory':{'MemAvailable':256*1024**2}},'load':[0],
                'config':dict(g.DEFAULT,max_rows=100),'generation':'MCG000001',
                'counters':[{'direction':'in','reason':'country','target':'DROP','packets':10,'bytes':100}],
                'interfaces':{'eth0':{'rx':1000,'tx':500}}}
    def test_sampling_collects_no_online_data(self):
        snap={'rows':[self.row()],'shown':1,'read_records':1,'available':True,'truncated':False}
        with patch.object(g,'connection_snapshot',return_value=snap),patch.object(g,'fetch') as fetch,patch.object(t,'boot_id',return_value='boot'):
            t.collect(self.state())
        fetch.assert_not_called()
        self.assertTrue((g.RUN/'telemetry-snapshot.json').exists())
    def test_sampling_due_time_respected(self):
        g.save_json(g.RUN/'telemetry-baseline.json',{'monotonic':100,'boot':'boot'})
        with patch.object(t,'boot_id',return_value='boot'),patch.object(t.time,'monotonic',return_value=120),patch.object(g,'connection_snapshot') as scan:
            t.collect(self.state())
        scan.assert_not_called()
    def test_high_load_defers_detail_collection(self):
        state=self.state();state['doctor']['memory']['MemAvailable']=1
        with patch.object(g,'connection_snapshot') as scan: t.collect(state)
        scan.assert_not_called()
        self.assertIn('deferred',g.read_json(g.RUN/'telemetry-health.json')['message'])
    def test_attach_reads_cached_statistics_only(self):
        with patch.object(g,'connection_snapshot') as scan,patch.object(g,'fetch') as fetch:
            result={};t.attach(result)
        scan.assert_not_called();fetch.assert_not_called()
        self.assertIn('telemetry',result)
    def test_status_does_not_duplicate_full_history(self):
        now=time.time()
        history=[{'at':now-i,'load':1,'interfaces':{'eth0':{'rx_bps':10,'tx_bps':20}}} for i in range(500)]
        g.save_json(g.RUN/'telemetry-history.json',history)
        state={};t.attach(state)
        self.assertEqual(len(state['telemetry']['history']),500)
        self.assertEqual(len(state['history']),180)
        self.assertEqual(set(state['history'][0]),{'at','load'})
    def test_conntrack_parser_preserves_directional_accounting(self):
        row=g.parse_connection('ipv4 2 tcp 6 42 ESTABLISHED src=10.10.10.10 dst=8.8.8.8 sport=12345 dport=443 packets=2 bytes=200 src=8.8.8.8 dst=1.1.1.1 sport=443 dport=12345 packets=3 bytes=400')
        self.assertEqual(row['original_bytes'],200);self.assertEqual(row['reply_bytes'],400)
        self.assertEqual(row['bytes'],600);self.assertEqual(row['reply_source'],'8.8.8.8')


class BootstrapTests(Sandbox):
    def package(self):
        files={'guard.py':'VERSION="0.3.0-beta"\n','updater.py':'# fixture\n','install.sh':'#!/bin/sh\nexit 99\n','VERSION':'0.3.0-beta\n','tools/install-online.sh':'#!/bin/sh\nexit 99\n'}
        manifest={'project':'MerlinWRTadvancedfirewall','schema':1,'install_protocol':1,'version':'0.3.0-beta',
                  'files':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in files.items()}}
        return files,manifest
    def archive(self, files, manifest, extra=None):
        path=self.root/'archive.zip'
        with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
            for name,text in files.items():z.writestr('root/'+name,text)
            z.writestr('root/manifest.json',json.dumps(manifest))
            if extra:z.writestr(*extra)
        return path
    def test_valid_package_extracts_without_executing_installer(self):
        files,manifest=self.package();target=self.root/'source'
        b.extract_checked(self.archive(files,manifest),target,manifest)
        self.assertIn('exit 99',(target/'install.sh').read_text())
    def test_manifest_tamper_rejected(self):
        files,manifest=self.package();files['install.sh']='tampered'
        with self.assertRaisesRegex(b.BootstrapError,'Checksum'):b.extract_checked(self.archive(files,manifest),self.root/'out',manifest)
    def test_zip_traversal_rejected(self):
        files,manifest=self.package()
        with self.assertRaises(b.BootstrapError):b.extract_checked(self.archive(files,manifest,('../bad','bad')),self.root/'out',manifest)
        self.assertFalse((self.root/'bad').exists())
    def test_zip_symlink_rejected(self):
        files,manifest=self.package()
        info=zipfile.ZipInfo('root/link');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaises(b.BootstrapError):b.extract_checked(self.archive(files,manifest,(info,'/etc/passwd')),self.root/'out',manifest)
    def test_unlisted_file_rejected(self):
        files,manifest=self.package()
        with self.assertRaises(b.BootstrapError):b.extract_checked(self.archive(files,manifest,('root/surprise','x')),self.root/'out',manifest)
    def test_missing_file_rejected(self):
        files,manifest=self.package();files.pop('updater.py')
        with self.assertRaises(b.BootstrapError):b.extract_checked(self.archive(files,manifest),self.root/'out',manifest)
    def test_duplicate_file_rejected(self):
        import warnings
        files,manifest=self.package()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            archive=self.archive(files,manifest,('root/install.sh','duplicate'))
        with self.assertRaises(b.BootstrapError):b.extract_checked(archive,self.root/'out',manifest)
    def test_old_package_requires_publication_of_bootstrap(self):
        _,manifest=self.package();manifest['files'].pop('tools/install-online.sh')
        with self.assertRaisesRegex(b.BootstrapError,'Publish version'):b.manifest_valid(manifest)
    def test_embedded_python_matches_source(self):
        text=(ROOT/'tools/install-online.sh').read_text()
        embedded=text.split("<<'MAFW_BOOTSTRAP_PY'\n",1)[1].rsplit('\nMAFW_BOOTSTRAP_PY\n',1)[0]
        self.assertEqual(embedded,(ROOT/'tools/bootstrap.py').read_text())
    def test_installers_embed_the_portable_logging_source(self):
        common=(ROOT/'tools/installer-log.sh').read_text()
        for name in ('install.sh','tools/install-online.sh'):
            self.assertIn(common,(ROOT/name).read_text())
    def test_one_command_matches_the_readme(self):
        command=(ROOT/'tools/install-command.txt').read_text().strip()
        self.assertIn(command,(ROOT/'README.md').read_text())
        self.assertNotIn('mktemp',command)
        self.assertNotIn('mkfifo',command)
    def test_script_failure_does_not_exit_calling_shell(self):
        # Invalid args exit before prerequisites, package installs or router writes.
        result=subprocess.run(['sh','-c','sh "$1" --invalid-option; rc=$?; printf "SSH_SHELL_ALIVE:%s\\n" "$rc"','test',str(ROOT/'install.sh')],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0)
        self.assertIn('SSH_SHELL_ALIVE:1',result.stdout)
        self.assertIn('Installation stopped',result.stdout)
        self.assertIn('Usage:',result.stdout)
        logs=re.findall(r'/tmp/mafw-install\.[0-9]+\.[0-9]+/output.log',result.stdout)
        self.assertTrue(logs)
        for name in set(logs):
            self.assertIn('Usage:',Path(name).read_text());Path(name).unlink();Path(name).parent.rmdir()


if __name__=='__main__':unittest.main()
