"""Offline logic tests. These do NOT emulate an Asus kernel, HTTP server or fastpath."""
import base64, copy, json, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import guard as g
import install_support as installer

class Isolated(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.patches=[patch.object(g,'DATA',self.root/'data'),patch.object(g,'RUN',self.root/'run'),
                      patch.object(g,'PUBLIC',self.root/'run/public'),patch.object(g,'EMERGENCY',self.root/'emergency')]
        for p in self.patches:p.start()
        g.setup()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def config(self,**kw):
        c=copy.deepcopy(g.DEFAULT);c.update(kw);return g.validate_config(c)
    def result(self,stdout='',code=0):return subprocess.CompletedProcess([],code,stdout,'')

class ValidationTests(Isolated):
    def test_default_disabled(self):self.assertFalse(self.config()['enabled'])
    def test_country_allowlist_sorted(self):self.assertEqual(self.config(countries=['nl','BE','nl'])['countries'],['BE','NL'])
    def test_empty_enabled_country_rejected(self):
        with self.assertRaises(g.GuardError):self.config(country_enabled=True,countries=[])
    def test_clear_country_disabled_allowed(self):self.assertEqual(self.config(country_enabled=False,countries=[])['countries'],[])
    def test_unknown_country_rejected(self):
        with self.assertRaises(g.GuardError):self.config(countries=['XX'])
    def test_enabled_needs_reputation(self):
        with self.assertRaises(g.GuardError):self.config(enabled=True,skynet=False,abuse=False)
    def test_boolean_not_string(self):
        with self.assertRaises(g.GuardError):self.config(enabled='false')
    def test_unknown_option(self):
        with self.assertRaises(g.GuardError):self.config(command='rm -rf /')
    def test_port_normalization(self):self.assertEqual(g.port_range('1000-2000'),'1000:2000')
    def test_port_edges(self):
        for v in ['0','65536','2000-1000','443;reboot','22 80','-1']:
            with self.subTest(v=v),self.assertRaises(g.GuardError):g.port_range(v)
    def test_restricted_rule(self):
        self.assertEqual(g.parse_extra('out -p tcp -d 8.8.8.8 --dport 853 -j DROP'),[('out',['-p','tcp','-d','8.8.8.8/32','--dport','853'])])
    def test_editor_rejects_unsafe_forms(self):
        for v in ['out -j ACCEPT','out -F raw','out -p tcp -j DROP;reboot','out -j RETURN','out --dport 22 -j DROP','out -p tcp -p udp -j DROP','out -d $(reboot) -j DROP']:
            with self.subTest(v=v),self.assertRaises(g.GuardError):g.parse_extra(v)
    def test_ipv6_rejected(self):
        with self.assertRaises(g.GuardError):g.as_network('2001:db8::/32')
    def test_public_rejects_local_or_wide(self):
        for v in ['10.10.10.1','192.168.0.0/16','127.0.0.1','0.0.0.0/0']:
            with self.subTest(v=v),self.assertRaises(g.GuardError):g.as_network(v,public=True)
    def test_statistics_cap(self):
        with self.assertRaises(g.GuardError):self.config(max_rows=999999)

class FeedTests(Isolated):
    def test_network_comments_dedup(self):self.assertEqual(g.parse_network_lines('# comment\n8.8.8.0/24 # note\n8.8.8.0/24\n'),['8.8.8.0/24'])
    def test_bad_download_never_empty_fallback(self):
        for data in ['','<html>error</html>','8.8.8.8\n; comment\n1.1.1.1;foo\nreboot']:
            with self.subTest(data=data),self.assertRaises(g.GuardError):g.parse_network_lines(data)
    def test_list_limit_no_truncation(self):
        with patch.object(g,'MAX_NETWORKS',1),self.assertRaises(g.GuardError):g.parse_network_lines('1.1.1.1\n8.8.8.8')
    def test_skynet_extract_only_known_sets(self):
        text='add Skynet-Blacklist 8.8.8.8 comment "test only"\nadd Other 1.1.1.1\nadd Skynet-UserBans 10.0.0.1\n'
        self.assertEqual(g.extract_skynet(text),['8.8.8.8/32'])
    def test_skynet_country_conflict(self):
        with patch.object(g,'command',return_value=self.result('add Skynet-BlockedRanges 8.8.8.0/24 comment "Country: us"')),self.assertRaises(g.GuardError):g.snapshot_skynet(True)
    def test_country_paths_discovered(self):
        paths=['CIDR/NL/Netherlands-ipv4-Hackers.Zone.txt','CIDR/Belgium/Belgium-ipv4-Hackers.Zone.txt','CIDR/NL/Netherlands-ipv6-Hackers.Zone.txt']
        self.assertEqual(set(g.map_country_paths(paths,g.country_names())),{'NL','BE'})
    def test_duplicate_country_rejected(self):
        with self.assertRaises(g.GuardError):g.map_country_paths(['CIDR/NL/NL-ipv4-Hackers.Zone.txt','CIDR/Netherlands/Netherlands-ipv4-Hackers.Zone.txt'],g.country_names())
    def test_abuse_threshold_applied_locally(self):
        body=json.dumps({'data':[{'ipAddress':'8.8.8.8','abuseConfidenceScore':100},{'ipAddress':'1.1.1.1','abuseConfidenceScore':40}]})
        self.assertEqual(g.parse_abuse_blacklist(body,90)[0],['8.8.8.8/32'])
    def test_abuse_invalid_score_rejected(self):
        with self.assertRaises(g.GuardError):g.parse_abuse_blacklist('{"data":[{"ipAddress":"8.8.8.8","abuseConfidenceScore":200}]}',90)
    def test_download_host_locked(self):
        for url in ['http://api.github.com/x','https://evil.example/x','https://user:pass@api.github.com/x','https://api.github.com:444/x']:
            with self.subTest(url=url),self.assertRaises(g.GuardError):g.fetch(url)

class RuleTests(Isolated):
    def rules(self,**kw):return g.compile_rules(self.config(**kw),'MCG000001',['eth0'])
    def test_country_before_reputation_before_ports(self):
        text=self.rules(country_enabled=True,countries=['NL'],abuse=True,ports=[{'direction':'both','protocol':'tcp','ports':'443','side':'remote'}])
        for d in ('in','out'):
            self.assertLess(text.index('mcg:'+d+':country'),text.index('mcg:'+d+':skynet'))
            self.assertLess(text.index('mcg:'+d+':skynet'),text.index('mcg:'+d+':abuse'))
            self.assertLess(text.index('mcg:'+d+':abuse'),text.index('mcg:'+d+':port1'))
    def test_all_packets_no_established_shortcut(self):
        text=self.rules();self.assertNotIn('ESTABLISHED',text);self.assertNotIn('ACCEPT',text)
    def test_country_negated_match_src_dst(self):
        text=self.rules(country_enabled=True,countries=['NL']);self.assertIn('! --match-set MCG000001G src',text);self.assertIn('! --match-set MCG000001G dst',text)
    def test_private_returns_before_country(self):
        text=self.rules(country_enabled=True,countries=['NL']);self.assertLess(text.index('mcg:in:local'),text.index('mcg:in:country'))
    def test_inbound_no_outbound_fallthrough(self):self.assertIn('-A MCG000001P -i eth0 -j MCG000001I\n-A MCG000001P -i eth0 -j RETURN',self.rules())
    def test_no_skynet_references_added_to_iptables(self):self.assertNotIn('--match-set Skynet-',self.rules())
    def test_remote_port_direction(self):
        text=self.rules(ports=[{'direction':'both','protocol':'udp','ports':'443','side':'remote'}]);self.assertIn('-A MCG000001I -p udp --sport 443',text);self.assertIn('-A MCG000001O -p udp --dport 443',text)
    def test_invalid_interface_cannot_inject(self):
        with self.assertRaises(g.GuardError):g.compile_rules(self.config(),'MCG000001',['eth0;reboot'])
    def test_low_memory_prevents_build(self):
        with patch.object(g,'memory',return_value={'MemAvailable':1024}),self.assertRaises(g.GuardError):g.build_generation(self.config(),{'geo':[],'skynet':[],'abuse':[]})

class StatusTests(Isolated):
    def test_acceleration_both_explicit_off(self):
        self.assertTrue(g.acceleration('Flow Learning : Disabled\nHW Acceleration : Disabled')['verified_off'])
    def test_acceleration_unknown_or_on_not_ready(self):
        for s in ['', 'Flow Learning : Disabled', 'Flow Learning : Enabled\nHW Acceleration : Disabled']:
            with self.subTest(s=s):self.assertFalse(g.acceleration(s)['verified_off'])
    def test_new_flow_label(self):self.assertTrue(g.acceleration('Flow Ucast Learning: Disabled\nHW Acceleration: Disabled')['verified_off'])
    def test_counter_parser(self):
        rows=g.parse_counters('[42:8400] -A MCG000001I -m set ! --match-set MCG000001G src -m comment --comment "mcg:in:country" -j DROP')
        self.assertEqual(rows[0]['packets'],42);self.assertEqual(rows[0]['reason'],'country')
    def test_conntrack_bytes(self):
        r=g.parse_connection('ipv4 2 tcp 6 120 ESTABLISHED src=10.10.10.2 dst=1.1.1.1 sport=12345 dport=443 packets=2 bytes=200 src=1.1.1.1 dst=8.8.8.8 sport=443 dport=54321 packets=3 bytes=300')
        self.assertEqual(r['bytes'],500);self.assertEqual(r['dport'],443)
    def test_missing_bytes_not_zero(self):self.assertIsNone(g.parse_connection('ipv4 2 udp 17 src=10.0.0.1 dst=1.1.1.1 sport=2000 dport=53')['bytes'])
    def test_ipv6_not_in_snapshot(self):self.assertIsNone(g.parse_connection('ipv6 10 tcp 6 src=::1 dst=::2'))
    def test_hooks_require_order_and_targets(self):
        raw=':MCG000001I - [0:0]\n:MCG000001O - [0:0]\n:MCG000001P - [0:0]\n-A PREROUTING -j MCG_PRE\n-A OUTPUT -j MCG_OUT\n-A MCG_PRE -j MCG000001P\n-A MCG_OUT -j MCG000001O\n'
        self.assertTrue(g.hooks_healthy(raw,{'gen':'MCG000001'}))
        self.assertFalse(g.hooks_healthy(raw.replace('-A PREROUTING -j MCG_PRE','-A PREROUTING -j Other\n-A PREROUTING -j MCG_PRE'),{'gen':'MCG000001'}))
        self.assertFalse(g.hooks_healthy(raw.replace('-A MCG_PRE -j MCG000001P',''),{'gen':'MCG000001'}))
    def test_emergency_never_healthy(self):
        g.EMERGENCY.touch();self.assertFalse(g.hooks_healthy('',{'gen':'MCG000001'}))

class LifecycleTests(Isolated):
    def candidate(self):
        return {'gen':'MCG000001','started':time.time(),'config':self.config(enabled=True),'bundle':{'geo':[],'skynet':['8.8.8.8/32'],'abuse':[],'created':time.time(),'meta':{}}}
    def test_stage_preflight_failure_no_switch(self):
        with patch.object(g,'doctor',return_value={'ready':False,'warnings':['fastpath']}),patch.object(g,'switch_generation') as sw,self.assertRaises(g.GuardError):g.stage(self.config(enabled=True))
        sw.assert_not_called()
    def test_candidate_requires_confirmation(self):
        new=self.candidate()
        with patch.object(g,'doctor',return_value={'ready':True}),patch.object(g,'collect_sources',return_value=new['bundle']),patch.object(g,'build_generation',return_value=new),patch.object(g.subprocess,'Popen'),patch.object(g,'switch_generation'):
            r=g.stage(new['config'])
        self.assertTrue(r['pending']);self.assertFalse((g.DATA/'confirmed.json').exists());self.assertTrue((g.RUN/'pending-timer.json').exists())
    def test_watchdog_failure_never_installs_candidate(self):
        new=self.candidate()
        with patch.object(g,'doctor',return_value={'ready':True}),patch.object(g,'collect_sources',return_value=new['bundle']),patch.object(g,'build_generation',return_value=new),patch.object(g.subprocess,'Popen',side_effect=OSError('test')),patch.object(g,'cleanup_generation'),patch.object(g,'switch_generation') as sw:
            with self.assertRaises(g.GuardError):g.stage(new['config'])
        sw.assert_not_called();self.assertFalse((g.RUN/'pending.json').exists())
    def test_rollback_deadline_ignores_wall_clock_changes(self):
        with patch.object(g.time,'monotonic',return_value=200),patch.object(g.time,'time',return_value=0):
            self.assertTrue(g.pending_expired({'expires':99999999999,'monotonic_expires':120}))
    def test_confirm_persists_exact_bundle(self):
        new=self.candidate();g.save_json(g.RUN/'pending.json',{'token':'abc','expires':time.time()+120,'old':None,'new':new,'config':new['config']})
        g.confirm('abc');self.assertEqual(g.read_json(g.DATA/'confirmed.json')['bundle'],new['bundle']);self.assertFalse((g.RUN/'pending.json').exists())
    def test_late_confirm_rolls_back(self):
        g.save_json(g.RUN/'pending.json',{'token':'abc','expires':0,'old':None,'new':None,'config':self.config()})
        with patch.object(g,'switch_generation') as sw,self.assertRaises(g.GuardError):g.confirm('abc')
        sw.assert_called_once_with(None)
    def test_country_denial_skips_online_lookup(self):
        new=self.candidate();new['config'].update(country_enabled=True,countries=['NL']);g.save_json(g.RUN/'active.json',new)
        with patch.object(g,'command',return_value=self.result(code=1)),patch.object(g,'fetch') as fetch:
            r=g.ip_lookup('1.1.1.1',online=True)
        self.assertTrue(r['blocked_by_country']);fetch.assert_not_called()
    def test_web_rejects_stale_request(self):
        with patch.object(g,'command',return_value=self.result('different')),patch.object(g,'handle') as handler,self.assertRaises(g.GuardError):g.web_request('12345678901234567890123')
        handler.assert_not_called()
    def test_disabled_periodic_refresh_no_fetch(self):
        with patch.object(g,'fetch') as f:g.refresh_sources()
        f.assert_not_called()

class InstallerTests(Isolated):
    def test_hook_insert_before_final_exit(self):
        text='#!/bin/sh\necho existing\nexit 0\n';result=installer.patch_hook(text,installer.HOOKS['firewall-start'])
        self.assertLess(result.index('# MCG-ADDON'),result.index('exit 0'));self.assertIn('echo existing',result)
    def test_hook_idempotent(self):
        a=installer.patch_hook('#!/bin/sh\n',installer.HOOKS['service-event']);self.assertEqual(a,installer.patch_hook(a,installer.HOOKS['service-event']))
    def test_hook_removal_preserves_skynet(self):
        src='#!/bin/sh\nsh /jffs/scripts/firewall start skynetloc=/mnt/usb/skynet # Skynet\n'
        a=installer.patch_hook(src,installer.HOOKS['firewall-start']);self.assertEqual(installer.patch_hook(a),src)
    def test_non_shell_hook_not_modified(self):
        with self.assertRaises(g.GuardError):installer.patch_hook('#!/usr/bin/python3\nprint(1)\n','x')

if __name__=='__main__':unittest.main(verbosity=2)
