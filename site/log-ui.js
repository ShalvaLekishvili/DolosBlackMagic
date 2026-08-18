(function(){
'use strict';
const L=window.DBMLogEngine;if(!L)return;
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const $=s=>document.querySelector(s);
let result=null,filtered=[];

function inject(){
 const nav=$('.nav');if(nav&&!$('#blacklogNav')){const b=document.createElement('button');b.className='nav-item';b.id='blacklogNav';b.dataset.view='logs';b.textContent='BlackLog Intelligence';nav.insertBefore(b,nav.querySelector('[data-view="grimoire"]'));b.onclick=()=>show()}
 const main=$('.main');if(main&&!$('#view-logs')){const s=document.createElement('section');s.className='view';s.id='view-logs';s.innerHTML=`
 <div class="section-title"><span class="kicker">BLACKLOG ENGINE</span><h1>Log Intelligence</h1><p>Normalize heterogeneous security logs, detect suspicious behavior and correlate related events locally in your browser.</p></div>
 <div class="log-intake-grid">
   <div class="panel log-drop" id="logDrop"><input type="file" id="logFile" hidden accept=".log,.txt,.json,.jsonl,.ndjson,.csv,.cef,.leef"/><span class="kicker">INGEST</span><h2>Drop security logs</h2><p>JSON · NDJSON · CSV · Syslog · CEF · LEEF · key=value · plain text</p><button class="ghost" id="browseLogs">Choose file</button></div>
   <div class="panel"><label>PASTE LOG STREAM</label><textarea class="mono log-textarea" id="logText" placeholder="Paste Wazuh, Sysmon, Windows Event, Linux auth.log, firewall, web access, CEF/LEEF, JSON/NDJSON, CSV or syslog…"></textarea><div class="row"><button class="ghost" id="sampleLogs">Load detection sample</button><button class="primary" id="analyzeLogs">Analyze logs</button></div></div>
 </div>
 <div id="logWorkspace" class="hidden">
  <div class="log-metrics">
   <article><span>FORMAT</span><strong id="logFormat">—</strong><small>auto detected</small></article>
   <article><span>EVENTS</span><strong id="logEvents">0</strong><small>normalized</small></article>
   <article><span>DETECTIONS</span><strong id="logFindings">0</strong><small>rule + correlation</small></article>
   <article><span>CRITICAL / HIGH</span><strong id="logCritical">0</strong><small>priority findings</small></article>
  </div>
  <div class="grid two log-grid">
   <article class="panel"><div class="panel-head"><div><span class="kicker">DETECTION QUEUE</span><h2>Findings</h2></div><span class="badge" id="ruleCount">0 rules</span></div><div id="findingList" class="finding-queue"></div></article>
   <article class="panel"><div class="panel-head"><div><span class="kicker">TELEMETRY PROFILE</span><h2>Observed entities</h2></div></div><div id="logProfile"></div></article>
  </div>
  <div class="panel log-console">
   <div class="panel-head"><div><span class="kicker">NORMALIZED EVENT CONSOLE</span><h2>Events</h2></div><div class="row"><button class="ghost" id="exportLogCsv">Export CSV</button><button class="ghost" id="exportLogJson">Export JSON</button></div></div>
   <div class="log-filters"><input id="logSearch" placeholder="Search message, host, IP, user, process…"><select id="logSeverity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option></select><select id="logSource"><option value="">All sources</option></select><label class="check"><input type="checkbox" id="detectionsOnly"> Detections only</label></div>
   <div class="log-table-wrap"><table class="log-table"><thead><tr><th>Time</th><th>Sev</th><th>Source</th><th>Event</th><th>Host / User</th><th>Source → Destination</th><th>Message</th></tr></thead><tbody id="logBody"></tbody></table></div>
   <div class="log-footer"><span id="logShown">0 events</span><span>Client-side processing · no log upload</span></div>
  </div>
 </div>`;main.appendChild(s);bind()}
}
function show(){document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-logs'));document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.id==='blacklogNav'));$('#sidebar')?.classList.remove('open')}
function bind(){
 const drop=$('#logDrop'),file=$('#logFile');$('#browseLogs').onclick=()=>file.click();drop.onclick=e=>{if(e.target.id!=='browseLogs')file.click()};['dragenter','dragover'].forEach(k=>drop.addEventListener(k,e=>{e.preventDefault();drop.classList.add('drag')}));['dragleave','drop'].forEach(k=>drop.addEventListener(k,e=>{e.preventDefault();drop.classList.remove('drag')}));drop.ondrop=e=>handleFile(e.dataTransfer.files[0]);file.onchange=e=>handleFile(e.target.files[0]);
 $('#analyzeLogs').onclick=()=>run($('#logText').value);$('#sampleLogs').onclick=()=>{$('#logText').value=sample();run($('#logText').value)};
 $('#logSearch').oninput=applyFilters;$('#logSeverity').onchange=applyFilters;$('#logSource').onchange=applyFilters;$('#detectionsOnly').onchange=applyFilters;
 $('#exportLogCsv').onclick=()=>result&&download('dolosblackmagic-normalized-events.csv',L.exportCsv(result.events),'text/csv');$('#exportLogJson').onclick=()=>result&&download('dolosblackmagic-log-analysis.json',JSON.stringify(result,null,2),'application/json');
}
async function handleFile(f){if(!f)return;if(f.size>35*1024*1024)return alert('BlackLog browser mode currently limits a single log file to 35 MB.');const text=await f.text();$('#logText').value=text;run(text)}
function run(text){if(!String(text).trim())return;try{result=L.analyzeLogs(text);render();$('#logWorkspace').classList.remove('hidden')}catch(e){console.error(e);alert('Could not parse this log stream. Try plain text, JSON/NDJSON, CSV, Syslog, CEF or LEEF.')}}
function render(){const s=result.summary;$('#logFormat').textContent=s.format.toUpperCase();$('#logEvents').textContent=s.total;$('#logFindings').textContent=s.findings;$('#logCritical').textContent=(s.findingSeverity.critical||0)+(s.findingSeverity.high||0);$('#ruleCount').textContent=L.RULES.length+' built-in rules';
 $('#findingList').innerHTML=result.findings.length?result.findings.slice(0,80).map(f=>`<div class="log-finding sev-${f.severity}"><div><span class="severity-pill ${f.severity}">${f.severity}</span><b>${esc(f.name)}</b></div><small>${esc(f.ruleId)} · ${f.mitre.join(', ')||'no ATT&CK mapping'} · ${f.eventIds.length} event${f.eventIds.length===1?'':'s'}${f.correlation?' · correlated':''}</small><code>${esc(f.srcIp||f.host||f.user||'')}</code></div>`).join(''):'<div class="empty"><h3>No built-in detections fired</h3><p>Events were still normalized and remain searchable below.</p></div>';
 $('#logProfile').innerHTML=`<div class="profile-grid"><div><span>Sources</span><b>${s.sources.length}</b><small>${esc(s.sources.slice(0,5).join(' · ')||'—')}</small></div><div><span>Hosts</span><b>${s.hosts.length}</b><small>${esc(s.hosts.slice(0,5).join(' · ')||'—')}</small></div><div><span>Source IPs</span><b>${s.srcIps.length}</b><small>${esc(s.srcIps.slice(0,5).join(' · ')||'—')}</small></div><div><span>Users</span><b>${s.users.length}</b><small>${esc(s.users.slice(0,5).join(' · ')||'—')}</small></div></div>`;
 const sel=$('#logSource');sel.innerHTML='<option value="">All sources</option>'+s.sources.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');applyFilters()}
function applyFilters(){if(!result)return;const q=$('#logSearch').value.toLowerCase(),sev=$('#logSeverity').value,src=$('#logSource').value,only=$('#detectionsOnly').checked;filtered=result.events.filter(e=>{const hay=[e.message,e.host,e.user,e.srcIp,e.dstIp,e.process,e.commandLine,e.eventId,e.source,e.url].join(' ').toLowerCase();return(!q||hay.includes(q))&&(!sev||e.severity===sev)&&(!src||e.source===src)&&(!only||e.detections.length)});renderTable()}
function renderTable(){const rows=filtered.slice(0,2500);$('#logBody').innerHTML=rows.length?rows.map(e=>`<tr class="${e.detections.length?'detected':''}"><td class="nowrap">${esc(e.timestamp.replace('T',' ').replace('Z',''))}</td><td><span class="severity-pill ${esc(e.severity)}">${esc(e.severity)}</span></td><td>${esc(e.source)}</td><td>${esc(e.eventId||'—')}</td><td><b>${esc(e.host||'—')}</b><small>${esc(e.user||'')}</small></td><td><code>${esc(e.srcIp||'—')}${e.srcPort?':'+esc(e.srcPort):''} → ${esc(e.dstIp||'—')}${e.dstPort?':'+esc(e.dstPort):''}</code></td><td class="message-cell">${e.detections.length?`<span class="detect-dot" title="${esc(e.detections.map(d=>d.name).join(', '))}"></span>`:''}${esc(e.message.slice(0,600))}</td></tr>`).join(''):'<tr><td colspan="7" class="muted-cell">No events match the current filters.</td></tr>';$('#logShown').textContent=`${filtered.length} matching / ${result.events.length} total${filtered.length>2500?' · first 2500 rendered':''}`}
function download(name,content,type){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([content],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500)}
function sample(){const base='2026-08-18T18:';const lines=[];for(let i=0;i<6;i++)lines.push(`<34>${base}0${i}:0${i}Z web01 sshd[22${i}]: Failed password for invalid user admin from 203.0.113.77 port 50${i} ssh2`);for(let p=20;p<32;p++)lines.push(`<134>${base}10:${String(p).padStart(2,'0')}Z fw01 firewall: action=deny src=198.51.100.23 dst=10.0.0.15 dpt=${p} proto=tcp`);lines.push(`<134>${base}20:00Z win01 Security: eventId=1102 host=WIN-DC01 user=admin message="The audit log was cleared"`);lines.push(`<134>${base}21:00Z win01 Security: eventId=4688 host=WIN-WS01 process=powershell.exe commandLine="powershell.exe -EncodedCommand SQBFAFgA" message="New process created powershell.exe -EncodedCommand SQBFAFgA"`);lines.push(`192.0.2.10 - - [18/Aug/2026:18:22:00 +0000] "GET /index.php?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 403 421`);return lines.join('\n')}
inject();
})();
