#!/usr/bin/env python3
"""Build a self-contained offline UI preview. All figures are synthetic."""
from pathlib import Path
import json,time,math
ROOT=Path(__file__).resolve().parent
now=int(time.time())
config={'enabled':True,'country_enabled':True,'countries':['BE','DE','NL'],'skynet':True,'abuse':False,'score':90,'ports':[{'direction':'both','protocol':'udp','ports':'443','side':'remote'}],'extra_rules':'# Example: owned DROP rules only\nout -p tcp --dport 853 -j DROP','max_rows':3000}
counters=[{'chain':'MCGdemoI','direction':'in','reason':'country','target':'DROP','packets':1234,'bytes':79104},{'chain':'MCGdemoO','direction':'out','reason':'country','target':'DROP','packets':267,'bytes':22304},{'chain':'MCGdemoI','direction':'in','reason':'skynet','target':'DROP','packets':98,'bytes':8232},{'chain':'MCGdemoO','direction':'out','reason':'port1','target':'DROP','packets':43,'bytes':5200},{'chain':'MCGdemoO','direction':'out','reason':'passed','target':'RETURN','packets':256820,'bytes':119541421}]
state={'version':'0.3.1-beta DEMO','at':now,'config':config,'active':True,'healthy':False,'generation':'DEMO','counters':counters,'doctor':{'model':'GT-AX11000 — EXAMPLE','firmware':'Not queried; offline demo','acceleration':{'flow':'demo','hardware':'demo','verified_off':False},'ipv6':'disabled (example)','warnings':[],'ready':False,'memory':{'MemAvailable':384*1024**2}},'warnings':['DEMO: all figures and connections are synthetic; no router is connected.'],'sources':{'NL':{'entries':4321,'fetched':now-43200,'commit':'demounverifiedsource'},'BE':{'entries':1842,'fetched':now-43200,'commit':'demounverifiedsource'},'DE':{'entries':5123,'fetched':now-43200,'commit':'demounverifiedsource'},'skynet':{'entries':32000,'fetched':now-1600}},'pending':None,'interfaces':{},'load':[.35,.31,.28],'history':[{'at':now-(179-i)*60,'load':.27+.1*math.sin(i/6)+.05*math.cos(i/3)} for i in range(180)],'key_configured':False,'connections':{'rows':[{'source':'10.10.10.10','destination':'192.0.2.21','sport':51433,'dport':443,'protocol':'tcp','state':'ESTABLISHED','bytes':2800345},{'source':'10.10.10.20','destination':'198.51.100.10','sport':54220,'dport':53,'protocol':'udp','state':'ASSURED','bytes':1660},{'source':'10.10.10.30','destination':'203.0.113.11','sport':59410,'dport':443,'protocol':'tcp','state':'ESTABLISHED','bytes':None}],'read_records':3,'shown':3,'truncated':False,'available':True,'note':'DEMO — synthetic data with reserved example addresses. No real connections.'}}
state['updates']={'repository':'wootje/MerlinWRTadvancedfirewall','branch':'main','version':'0.3.1-beta DEMO','installed_commit':'1'*40,'latest_commit':None,'latest_version':None,'last_check':None,'available':False,'staged':None,'backup':'/opt/var/backups/merlin-country-guard/DEMO','settings':{'auto_check':True,'auto_download':True},'message':'DEMO: no real GitHub request has been made.'}
# Extended demo data is explicitly synthetic and never queried from a router.
from tools.telemetry import summarize
state['updates']['settings'].update(enabled=True,interval_hours=24)
state['updates']['next_check']=now+86400
state['country_updates']={'settings':{'auto_update':True,'interval_hours':24},'last_success':now-43200,'next_check':now+43200,'entries':11286,'message':'DEMO: selected IPv4 country files; no live source was downloaded.'}
summary=summarize(state['connections']['rows'],20)
history=[]
for i in range(180):
    cpu=12+8*math.sin(i/10)+3*math.cos(i/5)
    rx=(25+15*math.sin(i/13))*1000000
    tx=(4+2*math.cos(i/11))*1000000
    history.append({'at':now-(179-i)*60,'generation':'DEMO','load':.27+.1*math.sin(i/6),'cpu_percent':cpu,'blocked_packets':12+i%13,'blocked_bytes':1500+i*10,'blocked_pps':(12+i%13)/60,'connections':3,'shown':3,'free':384*1024**2,'counter_gap':False,'interfaces':{'eth0':{'rx_bps':rx,'tx_bps':tx},'br0':{'rx_bps':tx,'tx_bps':rx}}})
interfaces={'eth0':{'rx':2148000000,'tx':154800000,'rx_bps':history[-1]['interfaces']['eth0']['rx_bps'],'tx_bps':history[-1]['interfaces']['eth0']['tx_bps']},'br0':{'rx':154800000,'tx':2148000000,'rx_bps':history[-1]['interfaces']['br0']['rx_bps'],'tx_bps':history[-1]['interfaces']['br0']['tx_bps']}}
state['telemetry']={'settings':{'interval_minutes':1,'retention_hours':24,'top_n':20},'sample':dict(history[-1],duration_ms=34.2,interval_seconds=60,total_memory=1024**3,conntrack_count=3,conntrack_max=32768,summary=summary,interfaces=interfaces,rule_deltas=[{'direction':'in','reason':'country','target':'DROP','packets':12,'bytes':864,'pps':.2},{'direction':'out','reason':'skynet','target':'DROP','packets':3,'bytes':216,'pps':.05}]),'history':history,'health':{},'notes':['DEMO: all figures are synthetic and no real traffic was analyzed.','Current connection rankings cover only the displayed sample. Flow bytes are cumulative for still-present flows, not interval traffic totals.','Blocked packets do not appear as blocked connections in conntrack. Interface totals must not be summed across bridges and VLANs.']}
state['history']=history
text='<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Advanced Firewall — interactive offline demo</title><style>body{margin:0;background:#111a24;padding:24px;font-family:Arial,sans-serif}'+(ROOT/'web/guard.css').read_text()+'</style></head><body>'+(ROOT/'web/body.html').read_text()+'<script>window.MCG_DEMO=true;window.MCG_COUNTRIES='+ (ROOT/'countries.json').read_text()+';window.MCG_DEMO_STATE='+json.dumps(state)+';</script><script>'+(ROOT/'web/guard.js').read_text()+'</script></body></html>'
(ROOT/'preview.html').write_text(text,encoding='utf-8')
print(ROOT/'preview.html')

# Preserve native Merlin scaffolding while replacing the shared add-on body.
asp=ROOT/'web/guard.asp'
old=asp.read_text()
start=old.index('<div id="mcg">')
end=old.index('</td></tr></table>',start)
asp.write_text(old[:start]+(ROOT/'web/body.html').read_text()+old[end:])
