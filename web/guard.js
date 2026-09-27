"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const demo = Boolean(window.MCG_DEMO);
  let updateDirty = false;
  let names = {}, chosen = new Set(), ports = [], state = null, busy = false, dirty = false, tableText = "";
  const number = v => v == null ? "—" : Number(v).toLocaleString("en-GB");
  const size = v => v == null ? "—" : v >= 1073741824 ? (v/1073741824).toFixed(2)+" GiB" : v >= 1048576 ? (v/1048576).toFixed(1)+" MiB" : v >= 1024 ? (v/1024).toFixed(1)+" KiB" : number(v)+" B";
  const date = v => v ? new Date(v*1000).toLocaleString("en-GB") : "—";
  const labels = {in:"Inbound",out:"Outbound",both:"Both",local:"Local/special-use",country:"Country not allowed",skynet:"Skynet reputation",abuse:"AbuseIPDB",passed:"Continue to existing firewall",remote:"Remote peer",destination:"Destination",either:"Source or destination"};
  let displayNames;
  try {displayNames = new Intl.DisplayNames(["en"], {type:"region"});} catch (_) {}
  const cname = c => displayNames ? displayNames.of(c) : (names[c]?.name || c);
  function msg(text, bad=false, good=false) {$("message").textContent=text;$("message").className="banner"+(bad?" bad":good?" good":"");}
  function mark() {dirty=true;$("dirtyLabel").textContent="Draft changed — not applied yet.";}
  function tdRow(parent, values) {const tr=document.createElement("tr"); values.forEach(v=>{const td=document.createElement("td");td.textContent=v==null?"—":String(v);tr.appendChild(td);});parent.appendChild(tr);return tr;}
  function download(name, text, type="text/plain") {const a=document.createElement("a");const url=URL.createObjectURL(new Blob([text],{type:type+";charset=utf-8"}));a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function csv(name, headers, rows) {const q=x=>'"'+String(x??"").replace(/"/g,'""')+'"';download(name,"\ufeff"+[headers,...rows].map(r=>r.map(q).join(";")).join("\r\n"),"text/csv");}
  function config() {return {enabled:$("enabled").checked,country_enabled:$("countryEnabled").checked,countries:[...chosen].sort(),skynet:$("skynet").checked,abuse:$("abuse").checked,score:Number($("score").value),ports:ports.map(x=>({...x})),extra_rules:$("extraRules").value,max_rows:Number($("maxRows").value)};}
  function fill(c) {$("enabled").checked=c.enabled;$("countryEnabled").checked=c.country_enabled;$("skynet").checked=c.skynet;$("abuse").checked=c.abuse;$("score").value=c.score;$("extraRules").value=c.extra_rules||"";$("maxRows").value=c.max_rows;chosen=new Set(c.countries);ports=c.ports.map(x=>({...x}));renderCountries();renderPorts();dirty=false;$("dirtyLabel").textContent="Draft matches the displayed router configuration.";}
  function renderCountries() {
    const term=$("countrySearch").value.trim().toLowerCase(), box=$("countryList");box.replaceChildren();
    const codes=Object.keys(names).sort((a,b)=>cname(a).localeCompare(cname(b),"en"));
    codes.filter(cc=>!term||[cc,cname(cc),names[cc].name].join(" ").toLowerCase().includes(term)).forEach(cc=>{const label=document.createElement("label"),inp=document.createElement("input"),text=document.createElement("span"),code=document.createElement("span");inp.type="checkbox";inp.checked=chosen.has(cc);inp.setAttribute("aria-label",cname(cc));inp.addEventListener("change",()=>{inp.checked?chosen.add(cc):chosen.delete(cc);mark();renderChips();});text.textContent=cname(cc);code.className="code";code.textContent=cc;label.append(inp,text,code);box.appendChild(label);});renderChips();
  }
  function renderChips(){const box=$("selectedChips");box.replaceChildren();[...chosen].sort().forEach(cc=>{const chip=document.createElement("span");chip.className="chip";chip.textContent=cname(cc);box.appendChild(chip);});$("selectionCount").textContent=chosen.size+" selected";}
  function renderPorts(){const box=$("portRows");box.replaceChildren();ports.forEach((p,i)=>{const tr=tdRow(box,[labels[p.direction],p.protocol.toUpperCase(),p.ports,labels[p.side],""]);const button=document.createElement("button");button.textContent="Remove";button.addEventListener("click",()=>{ports.splice(i,1);renderPorts();mark();});tr.lastChild.appendChild(button);});if(!ports.length)tdRow(box,["No port rules added.","","","",""]);}
  function filteredConnections(){
    const q=$("connectionSearch").value.toLowerCase(), p=$("connectionProto").value, d=$("connectionDirection").value;
    const rows=(state?.connections?.rows||[]).filter(r=>(!p||r.protocol===p)&&(!d||r.direction===d)&&(!q||Object.values(r).join(" ").toLowerCase().includes(q)));
    const order=$("connectionSort").value;
    if(order==="bytes")rows.sort((a,b)=>(b.bytes??-1)-(a.bytes??-1));
    if(order==="destination")rows.sort((a,b)=>a.destination.localeCompare(b.destination,"en",{numeric:true}));
    return rows;
  }

  function renderConnections(){const box=$("connectionRows");box.replaceChildren();filteredConnections().slice(0,250).forEach(r=>tdRow(box,[r.source,r.destination,r.protocol.toUpperCase(),r.sport,r.dport,r.state,size(r.bytes)]));const s=state?.connections||{};$("snapshotNote").textContent=(s.note||"")+" Read: "+number(s.read_records)+". Collected: "+number(s.shown)+". Filtered: "+number(filteredConnections().length)+(s.truncated?". The snapshot is limited.":"");}
  function renderChart(history){
    const svg=$("loadChart");svg.replaceChildren();const list=(history||[]).slice(-180);
    const text=(x,y,value)=>{const t=document.createElementNS("http://www.w3.org/2000/svg","text");t.setAttribute("x",x);t.setAttribute("y",y);t.setAttribute("fill","#acbdd0");t.setAttribute("font-size","10");t.textContent=value;svg.appendChild(t);};
    if(list.length<2){text(12,50,"Not enough measurement points yet");return;}
    const max=Math.max(1,Math.ceil(Math.max(...list.map(x=>x.load||0))*10)/10);
    const line=document.createElementNS("http://www.w3.org/2000/svg","line");line.setAttribute("x1",43);line.setAttribute("x2",795);line.setAttribute("y1",106);line.setAttribute("y2",106);line.setAttribute("stroke","#34465b");svg.appendChild(line);
    const poly=document.createElementNS("http://www.w3.org/2000/svg","polyline");poly.setAttribute("points",list.map((v,i)=>(45+i/(list.length-1)*745)+","+(106-(v.load||0)/max*87)).join(" "));poly.setAttribute("fill","none");poly.setAttribute("stroke","#70d8c4");poly.setAttribute("stroke-width","2.5");svg.appendChild(poly);
    text(6,20,max.toFixed(1));text(6,108,"0.0");
    const clock=t=>new Date(t*1000).toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"});
    text(45,126,clock(list[0].at));text(755,126,clock(list[list.length-1].at));
  }
  function render(s,force=false){state=s;if(!dirty||force)fill(s.config);$("kCountries").textContent=number(s.config.countries.length);$("kBlocked").textContent=number((s.counters||[]).filter(x=>x.target==="DROP").reduce((n,x)=>n+x.packets,0));$("kConnections").textContent=number(s.connections?.read_records);$("kMemory").textContent=size(s.doctor?.memory?.MemAvailable);$("coverage").textContent=s.healthy?"Active chains found and Flow Cache/Runner reported off by preflight. Actual operation still needs validation on your router.":s.active?"Rules are present, but full coverage is not confirmed. Review the warnings.":"Advanced Firewall is inactive. Existing Merlin/Skynet protection is not replaced.";const warningBox=$("warnings");warningBox.replaceChildren();(s.warnings||[]).forEach(w=>{const p=document.createElement("p");p.className="banner bad small";p.textContent=w;warningBox.appendChild(p);});$("keyState").textContent=s.key_configured?"An API key is configured on the router.":"No API key configured yet; the additional AbuseIPDB list is optional.";const sr=$("sourceRows");sr.replaceChildren();Object.entries(s.sources||{}).forEach(([k,v])=>tdRow(sr,[names[k]?cname(k):k,number(v.entries),date(v.fetched),v.commit?v.commit.slice(0,12):v.score?"score ≥ "+v.score:"local copy"]));const cr=$("counterRows");cr.replaceChildren();(s.counters||[]).forEach(r=>tdRow(cr,[labels[r.direction]||r.direction,labels[r.reason]||r.reason,r.target,number(r.packets),size(r.bytes)]));$("doctorText").textContent=JSON.stringify(s.doctor,null,2);$("pendingBox").classList.toggle("hidden",!s.pending);renderConnections();renderChart(s.history);renderUpdates(s.updates);renderCountryUpdates(s.country_updates);renderTelemetry(s.telemetry);}
  function randomId(){const a=new Uint32Array(2);crypto.getRandomValues(a);return String(Date.now())+String(a[0]).padStart(10,"0");}
  async function request(payload){if(busy)throw Error("A management operation is already in progress.");busy=true;$("apply").disabled=true;try{if(demo)return await demoRequest(payload);const id=randomId();const encoded=btoa(unescape(encodeURIComponent(JSON.stringify(payload))));if(encoded.length>7000)throw Error("Draft too large for the Merlin Addons API.");const form=document.forms.mcgform;form.amng_custom.value=JSON.stringify({mcg_request:id,mcg_payload:encoded});form.action_script.value="start_MCG_"+id;form.current_page.value=location.pathname.replace(/^\//,"");form.next_page.value=form.current_page.value;form.submit();form.amng_custom.value="";for(let n=0;n<375;n++){await new Promise(r=>setTimeout(r,1600));let response;try{response=await fetch("/ext/mcg/result.json?t="+Date.now(),{cache:"no-store",credentials:"same-origin"});if(!response.ok)continue;const result=await response.json();if(result.id!==id)continue;if(!result.ok)throw new Error(result.error||"Management operation failed.");return result.data;}catch(e){if(e instanceof SyntaxError)continue;if(response?.ok)throw e;}}throw Error("No result received. Check router status and SSH logs. An unconfirmed policy trial should be rolled back by its watchdog; software installation has separate recovery rules.");}finally{busy=false;$("apply").disabled=false;}}
  async function loadStatus(force=false){if(demo){render(window.MCG_DEMO_STATE,force);return;}const r=await fetch("/ext/mcg/status.json?t="+Date.now(),{cache:"no-store",credentials:"same-origin"});if(!r.ok)throw Error("Status file missing. Run /jffs/scripts/mcg status and check the installation.");render(await r.json(),force);}
  async function action(payload,done){msg("Running the management operation on the router…");try{const result=await request(payload);if(done)done(result);if(payload.action!=="lookup"&&payload.action!=="tables"&&payload.action!=="doctor"){await loadStatus(payload.action==="confirm"||payload.action==="rollback"||payload.action==="disable");}msg(result.message||"Management operation completed.",false,true);return result;}catch(e){msg(e.message,true);return null;}}
  function lookupResult(r){const box=$("lookupResult");box.replaceChildren();const p=document.createElement("p");p.className="banner";p.textContent=r.verdict;box.appendChild(p);if(r.online){const x=document.createElement("pre");x.textContent=JSON.stringify(r.online,null,2);box.appendChild(x);}for(const [label,url] of [["AlienVault OTX",r.otx],["AbuseIPDB",r.abuse_url]]){if(!url)continue;const a=document.createElement("a");a.textContent=label;a.href=url;a.target="_blank";a.rel="noopener noreferrer";a.className="button";box.appendChild(a);}if(r.online_note){const p=document.createElement("p");p.className="small muted";p.textContent=r.online_note;box.appendChild(p);}}

  function renderUpdates(u) {
    if (!u) return;
    $("updateRepo").textContent=u.repository;
    $("updateVersion").textContent=u.version || state.version;
    $("updateInstalled").textContent=u.installed_commit ? u.installed_commit.slice(0,12) : "Local installation; no commit baseline yet";
    $("updateLatestVersion").textContent=u.latest_version || "Not checked";
    $("updateLatest").textContent=u.latest_commit ? u.latest_commit.slice(0,12) : "Not checked";
    $("updateChecked").textContent=date(u.last_check);
    $("updateStaged").textContent=u.staged ? u.staged.version+" / "+u.staged.commit.slice(0,12) : "No update staged";
    $("updateMessage").textContent=u.message || "";
    $("updateError").textContent=u.error || "";
    $("updateError").classList.toggle("hidden",!u.error);
    const enabled=u.settings?.enabled!==false;
    $("updateCheck").disabled=!enabled || Boolean(state.pending);
    $("updateNextCheck").textContent=!enabled ? "GitHub updates disabled" : !u.settings.auto_check ? "Manual checks only" : date(u.next_check);
    $("updateInstall").disabled=!enabled || !u.staged || Boolean(state.pending);
    $("updateRollback").disabled=!u.backup || Boolean(state.pending);
    $("updateDownload").disabled=!enabled || !u.available || Boolean(state.pending);
    $("updateBackup").textContent=u.backup ? "Previous application backup: "+u.backup : "No previous application backup available.";
    const link=$("updateCommitLink");link.classList.toggle("hidden",!u.commit_url);
    if(u.commit_url && /^https:\/\/github\.com\/wootje\/MerlinWRTadvancedfirewall\/commit\/[0-9a-f]{40}$/.test(u.commit_url))link.href=u.commit_url;
    if(!updateDirty){$("updateEnabled").checked=u.settings?.enabled!==false;$("updateInterval").value=u.settings?.interval_hours||24;$("updateAutoCheck").checked=Boolean(u.settings?.auto_check);$("updateAutoDownload").checked=Boolean(u.settings?.auto_download);}
  }
  function bindUpdates() {
    $("updateEnabled").onchange=()=>{updateDirty=true;if(!$("updateEnabled").checked){$("updateAutoCheck").checked=false;$("updateAutoDownload").checked=false;}};
    $("updateInterval").onchange=()=>updateDirty=true;
    $("updateCheck").onclick=()=>action({action:"update-check"});
    $("updateDownload").onclick=()=>action({action:"update-download"});
    $("updateAutoCheck").onchange=()=>{updateDirty=true;if(!$("updateAutoCheck").checked)$("updateAutoDownload").checked=false;else $("updateEnabled").checked=true;};
    $("updateAutoDownload").onchange=()=>{updateDirty=true;if($("updateAutoDownload").checked){$("updateAutoCheck").checked=true;$("updateEnabled").checked=true;}};
    $("updateSave").onclick=()=>{try{action({action:"update-settings",settings:{enabled:$("updateEnabled").checked,interval_hours:integerField("updateInterval",1,720),auto_check:$("updateAutoCheck").checked,auto_download:$("updateAutoDownload").checked}},()=>{updateDirty=false;});}catch(e){msg(e.message,true);}};
    $("updateInstall").onclick=()=>{
      const u=state?.updates;
      if(!u?.staged)return;
      if(dirty){msg("Apply or reset the firewall draft before installing software.",true);return;}
      if(confirm("Install downloaded version "+u.staged.version+" at commit "+u.staged.commit.slice(0,12)+"? An application backup will be created. Keep SSH available. Reload this page after completion."))
        action({action:"update-install",commit:u.staged.commit});
    };
    $("updateRollback").onclick=()=>{if(confirm("Restore the previous application files? Current private settings and active firewall rules are retained. Reload this page afterwards."))action({action:"update-rollback"});};
  }

  function bind(){bindUpdates();bindExtended();document.querySelectorAll("#mcg [data-tab]").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll("#mcg [data-tab]").forEach(x=>x.classList.toggle("active",x===b));document.querySelectorAll("#mcg [data-panel]").forEach(x=>x.classList.toggle("hidden",x.dataset.panel!==b.dataset.tab));}));["enabled","countryEnabled","skynet","abuse","score","extraRules","maxRows"].forEach(id=>$(id).addEventListener("change",mark));$("countrySearch").addEventListener("input",renderCountries);$("clearCountries").onclick=()=>{chosen.clear();$("countryEnabled").checked=false;mark();renderCountries();};$("addPort").onclick=()=>{const v=$("portValue").value.trim();if(!/^\d{1,5}(?:[-:]\d{1,5})?$/.test(v)){msg("Enter a port or range.",true);return;}const a=v.split(/[-:]/).map(Number);if(a.some(x=>x<1||x>65535)||(a.length>1&&a[0]>a[1])){msg("Invalid port range.",true);return;}if(ports.length>=24){msg("Maximum 24 port rules.",true);return;}ports.push({direction:$("portDirection").value,protocol:$("portProtocol").value,ports:v,side:$("portSide").value});$("portValue").value="";mark();renderPorts();};$("apply").onclick=()=>{const c=config();if(c.country_enabled&&!c.countries.length){msg("Select at least one allowed country or disable the country filter.",true);return;}if(c.enabled&&!c.skynet&&!c.abuse){msg("Select at least one reputation source.",true);return;}if(c.abuse&&!state.key_configured){msg("Set the AbuseIPDB API key over SSH first.",true);return;}if(!confirm("Test the new firewall rules for up to 120 seconds? Connections may be interrupted."))return;action({action:"apply",config:c});};$("confirm").onclick=()=>state?.pending&&action({action:"confirm",token:state.pending.token});$("rollback").onclick=()=>state?.pending&&action({action:"rollback",token:state.pending.token});$("disable").onclick=()=>{if(confirm("Disable only this add-on? The original firewall will remain in place."))action({action:"disable"});};$("resetDraft").onclick=()=>state&&fill(state.config);$("refreshStatus").onclick=()=>action({action:"status"},r=>render(r));$("refreshFeeds").onclick=()=>action({action:"refresh"});$("lookupLocal").onclick=()=>action({action:"lookup",ip:$("lookupIp").value.trim(),online:false},lookupResult);$("lookupOnline").onclick=()=>action({action:"lookup",ip:$("lookupIp").value.trim(),online:true},lookupResult);$("readTables").onclick=()=>action({action:"tables"},r=>{tableText=r.text;$("tablesText").textContent=tableText;});$("tableSearch").oninput=()=>{const q=$("tableSearch").value.toLowerCase();$("tablesText").textContent=tableText.split("\n").filter(x=>!q||x.toLowerCase().includes(q)).join("\n");};$("exportTables").onclick=()=>tableText?download("advanced-firewall-iptables.txt",tableText):msg("Read the tables first.",true);$("doctor").onclick=()=>action({action:"doctor"},r=>$("doctorText").textContent=JSON.stringify(r,null,2));["connectionSearch","connectionProto"].forEach(id=>$(id).addEventListener("input",renderConnections));$("exportConnections").onclick=()=>csv("advanced-firewall-connections.csv",["source","destination","protocol","sport","dport","state","bytes"],filteredConnections().map(r=>[r.source,r.destination,r.protocol,r.sport,r.dport,r.state,r.bytes]));$("exportCounters").onclick=()=>csv("advanced-firewall-counters.csv",["direction","reason","target","packets","bytes"],(state?.counters||[]).map(r=>[r.direction,r.reason,r.target,r.packets,r.bytes]));}
  async function demoRequest(p){await new Promise(r=>setTimeout(r,150));const s=window.MCG_DEMO_STATE;if(p.action.startsWith("update-"))return demoUpdate(p,s);
    if(p.action==="country-settings"){s.country_updates.settings={...p.settings};s.country_updates.next_check=p.settings.auto_update?Date.now()/1000+p.settings.interval_hours*3600:null;return{message:"DEMO: country update preferences saved; no router changed."};}
    if(p.action==="country-refresh"){s.country_updates.last_success=Date.now()/1000;s.country_updates.message="DEMO: selected country data refresh simulated; no files downloaded.";return{message:s.country_updates.message};}
    if(p.action==="stats-settings"){s.telemetry.settings={...p.settings};return{message:"DEMO: sampling preferences saved locally."};}
    if(p.action==="stats-refresh"){s.telemetry.sample.at=Date.now()/1000;return{message:"DEMO: sample refresh simulated; these are not real router measurements."};}
if(p.action==="apply"){s.demoOld={config:structuredClone(s.config),active:s.active,healthy:s.healthy};s.config=p.config;s.pending={token:"demo",expires:Date.now()/1000+120};s.active=p.config.enabled;return{message:"DEMO: draft changed. Your router was not modified."};}if(p.action==="confirm"||p.action==="rollback"){if(p.action==="rollback"&&s.demoOld){s.config=s.demoOld.config;s.active=s.demoOld.active;s.healthy=s.demoOld.healthy;}delete s.demoOld;s.pending=null;return{message:"DEMO: action processed; no router changes."};}if(p.action==="disable"){s.active=false;s.healthy=false;s.config.enabled=false;return{message:"DEMO: add-on filtering disabled."};}if(p.action==="tables")return{text:"# DEMO — no real router data\n*raw\n:MCG_PRE - [0:0]\n-A PREROUTING -j MCG_PRE\nCOMMIT\n"};if(p.action==="lookup")return{ip:p.ip,verdict:"DEMO: no real reputation check was performed.",otx:"https://otx.alienvault.com/indicator/ip/"+encodeURIComponent(p.ip),abuse_url:"https://www.abuseipdb.com/check/"+encodeURIComponent(p.ip)};if(p.action==="doctor")return s.doctor;if(p.action==="status")return s;return{message:"DEMO: nothing was downloaded."};}

  function demoUpdate(p,s) {
    const u=s.updates;
    if(p.action==="update-settings"){u.settings={...p.settings};u.next_check=p.settings.enabled&&p.settings.auto_check?Date.now()/1000+p.settings.interval_hours*3600:null;return {message:"DEMO: update preferences saved locally."};}
    if(p.action==="update-check" || p.action==="update-download"){
      u.last_check=Date.now()/1000;u.latest_commit="2".repeat(40);u.latest_version="0.3.1-beta DEMO";u.available=true;
      u.commit_url=null;
      if(u.settings.auto_download || p.action==="update-download")u.staged={commit:u.latest_commit,version:u.latest_version,at:Date.now()/1000};
      u.message=u.staged?"DEMO: a downloaded update is simulated. No network requests were made.":"DEMO: repository changes simulated. No download performed.";
      return {message:u.message};
    }
    if(p.action==="update-install"){
      u.version=u.staged.version;u.installed_commit=u.staged.commit;u.available=false;u.staged=null;u.message="DEMO: installation simulated. No router files changed.";return {message:u.message};
    }
    if(p.action==="update-rollback"){u.version="0.3.1-beta DEMO";u.installed_commit="1".repeat(40);u.message="DEMO: application rollback simulated.";return {message:u.message};}
    throw Error("Unknown demo update action.");
  }

  let countryUpdateDirty = false, statsDirty = false;
  const rate = v => v == null ? "—" : (v / 1000000).toFixed(3) + " Mbit/s";
  function integerField(id, lo, hi) {
    const n = Number($(id).value);
    if (!Number.isInteger(n) || n < lo || n > hi) throw Error("Enter an integer from " + lo + " to " + hi + ".");
    return n;
  }
  function renderCountryUpdates(u) {
    if (!u) return;
    if (!countryUpdateDirty) {
      $("countryAutoUpdate").checked = Boolean(u.settings.auto_update);
      $("countryInterval").value = u.settings.interval_hours;
    }
    $("countryLastSuccess").textContent = date(u.last_success);
    $("countryNextCheck").textContent = u.settings.auto_update ? (u.next_check ? date(u.next_check) : "Due at the next scheduler run") : "Automatic updates disabled";
    $("countryEntries").textContent = number(u.entries);
    $("countryUpdateMessage").textContent = u.message || "Not checked yet.";
    $("countryUpdateError").textContent = u.error || "";
    $("countryUpdateError").classList.toggle("hidden", !u.error);
    $("countryRefresh").disabled = Boolean(state.pending);
  }
  function historyRows() {
    const history = state?.telemetry?.history || [];
    const cutoff = Date.now() / 1000 - Number($("statsWindow").value) * 3600;
    return history.filter(r => r.at >= cutoff);
  }
  function drawSeries(id, history, series) {
    const svg = $(id); svg.replaceChildren();
    const add = (tag, attrs, text) => {
      const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
      Object.entries(attrs).forEach(([k,v]) => el.setAttribute(k, v));
      if (text != null) el.textContent = text;
      svg.appendChild(el); return el;
    };
    const label = (x,y,t) => add("text", {x,y,fill:"#acbdd0","font-size":10}, t);
    if (history.length < 2) { label(12,50,"Waiting for two usable samples"); return; }
    const stride = Math.max(1, Math.ceil(history.length / 600));
    const rows = history.filter((_,i) => i % stride === 0 || i === history.length - 1);
    const values = series.flatMap(s => rows.map(s.value)).filter(v => typeof v === "number" && Number.isFinite(v));
    if (!values.length) { label(12,50,"No measured values for this metric yet"); return; }
    const max = Math.max(.01, ...values), t0 = rows[0].at, span = Math.max(1, rows[rows.length-1].at - t0);
    add("line",{x1:44,x2:795,y1:105,y2:105,stroke:"#34465b"});
    series.forEach((s,index) => {
      let points = [];
      const flush = () => {if(points.length > 1) add("polyline",{points:points.join(" "),fill:"none",stroke:s.color,"stroke-width":2}); points=[];};
      rows.forEach(row => {
        const value = s.value(row);
        if (typeof value !== "number" || !Number.isFinite(value)) {flush();return;}
        points.push((45+(row.at-t0)/span*745)+","+(105-value/max*80));
      }); flush();
      label(460+index*160,14,s.label);
      add("line",{x1:441+index*160,x2:455+index*160,y1:10,y2:10,stroke:s.color,"stroke-width":3});
    });
    label(4,25,max.toFixed(max < 10 ? 2 : 0)); label(4,107,"0");
    const clock = v => new Date(v*1000).toLocaleString("en-GB",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"});
    label(45,125,clock(t0)); label(688,125,clock(t0+span));
  }
  function renderHistory() {
    const rows = historyRows(), metric = $("statsMetric").value, iface = $("statsInterface").value;
    const text = $("statsMetric").selectedOptions[0].textContent;
    $("statsChartTitle").textContent = text;
    drawSeries("statsChart",rows,[{label:text,color:"#70d8c4",value:r=>r[metric]}]);
    drawSeries("trafficChart",rows,[
      {label:"Receive",color:"#70d8c4",value:r=>r.interfaces?.[iface]?.rx_bps == null ? null : r.interfaces[iface].rx_bps/1000000},
      {label:"Transmit",color:"#9aaefe",value:r=>r.interfaces?.[iface]?.tx_bps == null ? null : r.interfaces[iface].tx_bps/1000000}
    ]);
  }
  function rankingRows() { return state?.telemetry?.sample?.summary?.[$("statsGroup").value] || []; }
  function renderRanking() {
    const box = $("rankingRows"); box.replaceChildren();
    rankingRows().forEach(r => tdRow(box,[r.label,number(r.connections),r.accounted_rows ? size(r.known_bytes) : "Unavailable",r.accounted_rows+" / "+r.connections]));
    if (!rankingRows().length) tdRow(box,["No observed rows in this group.","","",""]);
  }
  function renderTelemetry(t) {
    if (!t) return;
    if (!statsDirty) {
      $("statsInterval").value = t.settings.interval_minutes;
      $("statsRetention").value = t.settings.retention_hours;
      $("statsTopN").value = t.settings.top_n;
    }
    const s = t.sample || {}, summary = s.summary || {};
    $("statCpu").textContent = s.cpu_percent == null ? "—" : s.cpu_percent.toFixed(1) + "%";
    $("statDropRate").textContent = number(s.blocked_pps);
    $("statUnique").textContent = number(summary.unique_local) + " / " + number(summary.unique_remote);
    $("statConntrack").textContent = s.conntrack_count != null && s.conntrack_max ? (s.conntrack_count/s.conntrack_max*100).toFixed(1)+"%" : "—";
    $("statsSampleInfo").textContent = "Last sample: "+date(s.at)+". Collection: "+number(s.duration_ms)+" ms. Kernel entries: "+number(s.conntrack_count)+" / "+number(s.conntrack_max)+". Detail rows: "+number(s.shown)+". Browser times use your computer's timezone.";
    $("statsHealth").textContent = t.health?.message || "";
    $("statsHealth").classList.toggle("hidden", !t.health?.message);
    const notes = $("statsNotes"); notes.replaceChildren();
    (t.notes||[]).forEach(text => {const p=document.createElement("p");p.textContent=text;notes.appendChild(p);});
    const box = $("interfaceRows"); box.replaceChildren();
    Object.entries(s.interfaces||{}).forEach(([name,v]) => tdRow(box,[name,rate(v.rx_bps),rate(v.tx_bps),size(v.rx),size(v.tx)]));
    const select = $("statsInterface"), old = select.value;
    const names = Object.keys(s.interfaces||{}).sort();
    if (names.join("|") !== [...select.options].map(o=>o.value).join("|")) {
      select.replaceChildren();names.forEach(name=>{const o=document.createElement("option");o.value=name;o.textContent=name;select.appendChild(o);});
      select.value = names.includes(old) ? old : names.includes("eth0") ? "eth0" : names.find(n=>n!=="lo") || names[0] || "";
    }
    const deltas = $("deltaRows"); deltas.replaceChildren();
    (s.rule_deltas||[]).forEach(r=>tdRow(deltas,[labels[r.direction]||r.direction,labels[r.reason]||r.reason,r.target,number(r.packets),size(r.bytes),number(r.pps)]));
    renderRanking();renderHistory();
  }
  function bindExtended() {
    ["countryAutoUpdate","countryInterval"].forEach(id=>$(id).onchange=()=>countryUpdateDirty=true);
    $("countryUpdateSave").onclick=()=>{try{action({action:"country-settings",settings:{auto_update:$("countryAutoUpdate").checked,interval_hours:integerField("countryInterval",1,720)}},()=>{countryUpdateDirty=false;});}catch(e){msg(e.message,true);}};
    $("countryRefresh").onclick=()=>{if(!chosen.size){msg("Select at least one country to refresh.",true);return;}action({action:"country-refresh",countries:[...chosen].sort()});};
    ["statsInterval","statsRetention","statsTopN"].forEach(id=>$(id).onchange=()=>statsDirty=true);
    $("statsSave").onclick=()=>{try{action({action:"stats-settings",settings:{interval_minutes:integerField("statsInterval",1,60),retention_hours:integerField("statsRetention",1,168),top_n:integerField("statsTopN",5,50)}},()=>{statsDirty=false;});}catch(e){msg(e.message,true);}};
    $("statsRefresh").onclick=()=>action({action:"stats-refresh"});
    $("statsExport").onclick=()=>download("advanced-firewall-statistics.json",JSON.stringify({telemetry:state?.telemetry,connections:state?.connections,counters:state?.counters},null,2),"application/json");
    ["statsWindow","statsMetric","statsInterface"].forEach(id=>$(id).onchange=renderHistory);
    $("statsGroup").onchange=renderRanking;
    $("statsTopExport").onclick=()=>csv("advanced-firewall-ranking.csv",["group","observed_connections","known_flow_bytes","rows_with_accounting"],rankingRows().map(r=>[r.label,r.connections,r.accounted_rows?r.known_bytes:null,r.accounted_rows]));
    $("statsHistoryExport").onclick=()=>{const iface=$("statsInterface").value;csv("advanced-firewall-history.csv",["time_utc","generation","cpu_percent","load_average","blocked_packets_interval","blocked_bytes_interval","blocked_packets_per_second","read_records","shown_rows","available_memory_bytes","interface","receive_bits_per_second","transmit_bits_per_second","counter_gap"],historyRows().map(r=>[new Date(r.at*1000).toISOString(),r.generation,r.cpu_percent,r.load,r.blocked_packets,r.blocked_bytes,r.blocked_pps,r.connections,r.shown,r.free,iface,r.interfaces?.[iface]?.rx_bps,r.interfaces?.[iface]?.tx_bps,r.counter_gap]));};
    ["connectionDirection","connectionSort"].forEach(id=>$(id).onchange=renderConnections);
  }

  async function init(){bind();try{if(demo){names=window.MCG_COUNTRIES;$("previewNotice").classList.remove("hidden");}else{const r=await fetch("/ext/mcg/countries.json");if(!r.ok)throw Error("Country names could not be loaded.");names=await r.json();}await loadStatus();msg(demo?"Interactive demo with clearly marked synthetic data.":"Status loaded. Select your allowed countries and review preflight results.");}catch(e){msg(e.message,true);}setInterval(()=>{if(state?.pending){const sec=Math.max(0,Math.ceil(state.pending.expires-Date.now()/1000));$("countdown").textContent=sec+" seconds until rollback";}},1000);if(!demo)setInterval(()=>{if(!document.hidden&&!busy)loadStatus().catch(()=>{});},30000);}
  document.addEventListener("DOMContentLoaded",init);
})();
