(function(global){
'use strict';

const RULES=[
 {id:'WIN-4625',name:'Windows failed logon',severity:'medium',score:35,mitre:['T1110'],match:e=>String(e.eventId)==='4625'},
 {id:'WIN-1102',name:'Windows audit log cleared',severity:'critical',score:90,mitre:['T1070.001'],match:e=>String(e.eventId)==='1102'},
 {id:'WIN-4688-PS',name:'Suspicious PowerShell process creation',severity:'high',score:70,mitre:['T1059.001','T1027'],match:e=>String(e.eventId)==='4688'&&/powershell(?:\.exe)?[^\n]*(?:-enc|-encodedcommand|frombase64string|downloadstring)/i.test(e.message+' '+e.commandLine)},
 {id:'WIN-7045',name:'New Windows service installed',severity:'high',score:65,mitre:['T1543.003'],match:e=>String(e.eventId)==='7045'},
 {id:'WIN-4720',name:'Windows user account created',severity:'medium',score:45,mitre:['T1136.001'],match:e=>String(e.eventId)==='4720'},
 {id:'WIN-4732',name:'User added to local security group',severity:'high',score:60,mitre:['T1098'],match:e=>String(e.eventId)==='4732'},
 {id:'SYSMON-1-LOL',name:'Suspicious LOLBin execution',severity:'high',score:60,mitre:['T1218'],match:e=>String(e.eventId)==='1'&&/\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|wmic)(?:\.exe)?\b/i.test(e.message+' '+e.process+' '+e.commandLine)},
 {id:'SYSMON-3',name:'Suspicious network-capable process',severity:'medium',score:45,mitre:['T1049'],match:e=>String(e.eventId)==='3'&&/\b(?:powershell|cmd|wscript|cscript|mshta|rundll32)\.exe\b/i.test(e.process+' '+e.message)},
 {id:'LINUX-SSH-FAIL',name:'SSH authentication failure',severity:'medium',score:30,mitre:['T1110'],match:e=>/(?:failed password|authentication failure|invalid user)/i.test(e.message)&&/(?:sshd|ssh)/i.test(e.source+' '+e.message)},
 {id:'LINUX-SUDO',name:'Suspicious sudo authentication failure',severity:'medium',score:40,mitre:['T1548.003'],match:e=>/sudo/i.test(e.source+' '+e.message)&&/(?:authentication failure|incorrect password|not in the sudoers)/i.test(e.message)},
 {id:'WEB-SQLI',name:'Possible SQL injection probe',severity:'high',score:65,mitre:['T1190'],match:e=>/(?:union(?:\s|%20)+select|select(?:\s|%20).+from|sleep\(|benchmark\(|or(?:\s|%20)+1=1|%27|information_schema)/i.test(e.url+' '+e.message)},
 {id:'WEB-TRAVERSAL',name:'Path traversal probe',severity:'high',score:60,mitre:['T1190'],match:e=>/(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|\/)|\/etc\/passwd|win\.ini)/i.test(e.url+' '+e.message)},
 {id:'WEB-SHELL',name:'Web shell / command execution probe',severity:'critical',score:85,mitre:['T1059','T1505.003'],match:e=>/(?:cmd\.exe|\/bin\/sh|powershell(?:\.exe)?|whoami|wget\s+http|curl\s+http)/i.test(e.url+' '+e.message)&&/(?:GET|POST|request|http)/i.test(e.message+' '+e.source)},
 {id:'FW-DENY',name:'Firewall denied connection',severity:'low',score:15,mitre:['T1046'],match:e=>/(?:deny|denied|drop|blocked|reject)/i.test(e.action+' '+e.message)&&!!e.srcIp},
 {id:'GEN-ENCODED-PS',name:'Encoded PowerShell observed',severity:'high',score:70,mitre:['T1059.001','T1027'],match:e=>/powershell(?:\.exe)?[^\n]*(?:-enc|-encodedcommand)\b/i.test(e.message+' '+e.commandLine)},
 {id:'GEN-CRED-DUMP',name:'Credential dumping indicator',severity:'critical',score:90,mitre:['T1003'],match:e=>/\b(?:mimikatz|sekurlsa|lsass(?:\.exe)?|comsvcs\.dll.*minidump|procdump.*lsass|ntds\.dit)\b/i.test(e.message+' '+e.commandLine)},
 {id:'GEN-DEFENSE-EVASION',name:'Security control tampering',severity:'critical',score:85,mitre:['T1562.001'],match:e=>/(?:Set-MpPreference.+DisableRealtimeMonitoring|sc(?:\.exe)?\s+stop\s+(?:windefend|sense)|netsh.+firewall.+off)/i.test(e.message+' '+e.commandLine)}
];

const sevRank={critical:5,high:4,medium:3,low:2,informational:1};
function str(v){return v==null?'':String(v)}
function pick(o,paths){for(const p of paths){let v=o;for(const k of p.split('.')){if(v==null)break;v=v[k]}if(v!==undefined&&v!==null&&v!=='')return v}return''}
function iso(v){if(!v)return new Date().toISOString();const d=new Date(v);return isNaN(d)?str(v):d.toISOString()}
function parseKV(s){const o={};const re=/([A-Za-z0-9_.@-]+)=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s]+)/g;let m;while((m=re.exec(s))){let v=m[2];if((v.startsWith('"')&&v.endsWith('"'))||(v.startsWith("'")&&v.endsWith("'")))v=v.slice(1,-1);o[m[1]]=v}return o}
function csvLine(line){const out=[];let cur='',q=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'){if(q&&line[i+1]==='"'){cur+='"';i++}else q=!q}else if(c===','&&!q){out.push(cur);cur=''}else cur+=c}out.push(cur);return out}
function detectFormat(text=''){
 const s=str(text).trim();if(!s)return'empty';
 try{const j=JSON.parse(s);if(j)return'json'}catch{}
 const lines=s.split(/\r?\n/).filter(Boolean);if(lines.length>1&&lines.slice(0,Math.min(lines.length,10)).every(l=>{try{JSON.parse(l);return true}catch{return false}}))return'ndjson';
 if(/^CEF:\d+\|/m.test(s))return'cef'; if(/^LEEF:\d+(?:\.\d+)?\|/m.test(s))return'leef';
 if(/^<\d{1,3}>\d?\s?\d{4}-\d{2}-\d{2}T/m.test(s)||/^<\d{1,3}>[A-Z][a-z]{2}\s+\d+/m.test(s))return'syslog';
 if(lines[0]&&lines[0].includes(',')&&lines[0].split(',').length>=3&&/(time|date|timestamp|event|message|source|src|host)/i.test(lines[0]))return'csv';
 if(/(?:^|\s)[A-Za-z0-9_.-]+=(?:"[^"]*"|\S+)/m.test(s))return'kv';
 return'plain';
}
function parseCEF(line){const parts=line.split('|');const ext=parts.slice(7).join('|');return{vendor:parts[1],product:parts[2],version:parts[3],signature:parts[4],name:parts[5],severity:parts[6],...parseKV(ext)}}
function parseLEEF(line){const parts=line.split('|');const ext=parts.slice(5).join('|').replace(/\t/g,' ');return{vendor:parts[1],product:parts[2],version:parts[3],eventId:parts[4],...parseKV(ext)}}
function parseSyslog(line){const r=/^<(?<pri>\d{1,3})>(?:\d\s+)?(?<ts>\S+(?:\s+\S+\s+\S+)?)\s+(?<host>\S+)\s+(?<app>[^:\s]+)(?:\[(?<pid>\d+)\])?:?\s*(?<msg>.*)$/;const m=line.match(r);return m?{pri:m.groups.pri,timestamp:m.groups.ts,host:m.groups.host,app:m.groups.app,pid:m.groups.pid,message:m.groups.msg,raw:line}:{message:line,raw:line}}
function parseRows(text,format=detectFormat(text)){
 const s=str(text).trim();if(!s)return[];
 if(format==='json'){const j=JSON.parse(s);if(Array.isArray(j))return j;if(Array.isArray(j.events))return j.events;if(Array.isArray(j.data))return j.data;return[j]}
 if(format==='ndjson')return s.split(/\r?\n/).filter(Boolean).map(l=>JSON.parse(l));
 if(format==='csv'){const lines=s.split(/\r?\n/).filter(Boolean),headers=csvLine(lines.shift()).map(x=>x.trim());return lines.map(l=>{const vals=csvLine(l),o={};headers.forEach((h,i)=>o[h]=vals[i]??'');return o})}
 if(format==='cef')return s.split(/\r?\n/).filter(Boolean).map(parseCEF);
 if(format==='leef')return s.split(/\r?\n/).filter(Boolean).map(parseLEEF);
 if(format==='syslog')return s.split(/\r?\n/).filter(Boolean).map(parseSyslog);
 if(format==='kv')return s.split(/\r?\n/).filter(Boolean).map(l=>({message:l,...parseKV(l)}));
 return s.split(/\r?\n/).filter(Boolean).map((l,i)=>({message:l,line:i+1}));
}
function normalize(row,i,format){
 const win=pick(row,['win','windows'])||{};
 const timestamp=pick(row,['@timestamp','timestamp','time','event.created','event.ingested','datetime','date','TimeCreated','win.system.systemTime','data.timestamp','devTime','rt','start']);
 const message=pick(row,['message','msg','Message','event.original','rule.description','win.system.message','data.message','name','eventName'])||JSON.stringify(row).slice(0,3000);
 const eventId=pick(row,['event.code','event_id','eventId','EventID','EventId','id','win.system.eventID','data.win.system.eventID','signature']);
 const srcIp=pick(row,['source.ip','src_ip','srcip','src','sourceAddress','client.ip','remote_addr','data.srcip','win.eventdata.ipAddress']);
 const dstIp=pick(row,['destination.ip','dst_ip','dstip','dst','destinationAddress','server.ip','data.dstip']);
 const srcPort=pick(row,['source.port','src_port','srcport','spt','data.srcport']);
 const dstPort=pick(row,['destination.port','dst_port','dstport','dpt','data.dstport']);
 const user=pick(row,['user.name','username','user','account','subjectUserName','targetUserName','win.eventdata.targetUserName','data.dstuser']);
 const host=pick(row,['host.name','hostname','host','computer_name','deviceHostname','win.system.computer','agent.name','data.agent.name']);
 const process=pick(row,['process.name','process','Image','image','win.eventdata.image','data.win.eventdata.image','app']);
 const commandLine=pick(row,['process.command_line','commandLine','CommandLine','win.eventdata.commandLine','data.win.eventdata.commandLine']);
 const action=pick(row,['event.action','action','act','disposition','outcome','rule.action']);
 const url=pick(row,['url.full','url','request','request_uri','uri','cs-uri-stem','data.url']);
 const source=pick(row,['event.module','event.dataset','source','program','app','product','rule.groups.0','agent.type'])||format;
 let severity=str(pick(row,['event.severity','severity','level','rule.level','sev'])).toLowerCase();
 if(/^\d+$/.test(severity)){const n=+severity;severity=n>=12?'critical':n>=8?'high':n>=4?'medium':n>0?'low':'informational'}
 if(!sevRank[severity])severity='informational';
 return{id:i+1,timestamp:iso(timestamp),format,source:str(source),host:str(host),eventId:str(eventId),severity,message:str(message),srcIp:str(srcIp),dstIp:str(dstIp),srcPort:str(srcPort),dstPort:str(dstPort),user:str(user),process:str(process),commandLine:str(commandLine),action:str(action),url:str(url),raw:row,detections:[]};
}
function applyRules(events){
 const findings=[];for(const e of events){for(const r of RULES){let hit=false;try{hit=!!r.match(e)}catch{}if(hit){const f={ruleId:r.id,name:r.name,severity:r.severity,score:r.score,mitre:r.mitre,eventIds:[e.id],timestamp:e.timestamp,srcIp:e.srcIp,user:e.user,host:e.host};e.detections.push(f);findings.push(f)}}}
 return findings;
}
function correlate(events,findings){
 function add(ruleId,name,severity,score,mitre,group){const ids=group.map(x=>x.id),first=group[0];const f={ruleId,name,severity,score,mitre,eventIds:ids,timestamp:first.timestamp,srcIp:first.srcIp,user:first.user,host:first.host,correlation:true};findings.push(f);group.forEach(e=>e.detections.push(f))}
 const auth=events.filter(e=>e.detections.some(d=>d.ruleId==='WIN-4625'||d.ruleId==='LINUX-SSH-FAIL'));
 const buckets=new Map();for(const e of auth){const k=e.srcIp||e.user||e.host||'unknown';if(!buckets.has(k))buckets.set(k,[]);buckets.get(k).push(e)}
 for(const arr of buckets.values()){arr.sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));for(let i=0;i<arr.length;i++){const win=arr.filter((e,j)=>j>=i&&new Date(e.timestamp)-new Date(arr[i].timestamp)<=300000);if(win.length>=5){add('CORR-BRUTEFORCE','Repeated authentication failures','high',75,['T1110'],win);break}}}
 const net=events.filter(e=>e.srcIp&&e.dstPort);const srcs=new Map();for(const e of net){if(!srcs.has(e.srcIp))srcs.set(e.srcIp,[]);srcs.get(e.srcIp).push(e)}
 for(const arr of srcs.values()){arr.sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));for(let i=0;i<arr.length;i++){const win=arr.filter((e,j)=>j>=i&&new Date(e.timestamp)-new Date(arr[i].timestamp)<=120000);if(new Set(win.map(e=>e.dstPort).filter(Boolean)).size>=10){add('CORR-PORTSCAN','Potential port scan','high',70,['T1046'],win);break}}}
 return findings;
}
function summarize(events,findings,format){
 const bySeverity={critical:0,high:0,medium:0,low:0,informational:0};events.forEach(e=>bySeverity[e.severity]=(bySeverity[e.severity]||0)+1);
 const fsev={critical:0,high:0,medium:0,low:0};findings.forEach(f=>fsev[f.severity]=(fsev[f.severity]||0)+1);
 return{format,total:events.length,findings:findings.length,bySeverity,findingSeverity:fsev,sources:[...new Set(events.map(e=>e.source).filter(Boolean))].slice(0,50),hosts:[...new Set(events.map(e=>e.host).filter(Boolean))].slice(0,50),srcIps:[...new Set(events.map(e=>e.srcIp).filter(Boolean))].slice(0,100),users:[...new Set(events.map(e=>e.user).filter(Boolean))].slice(0,100)};
}
function analyzeLogs(text=''){
 const format=detectFormat(text),rows=parseRows(text,format),events=rows.map((r,i)=>normalize(r,i,format)).sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
 const findings=correlate(events,applyRules(events));findings.sort((a,b)=>(sevRank[b.severity]||0)-(sevRank[a.severity]||0)||new Date(a.timestamp)-new Date(b.timestamp));
 return{format,events,findings,summary:summarize(events,findings,format)};
}
function exportCsv(events){const cols=['timestamp','severity','source','host','eventId','srcIp','dstIp','srcPort','dstPort','user','process','action','url','message'];const q=v=>'"'+str(v).replace(/"/g,'""')+'"';return[cols.join(','),...events.map(e=>cols.map(c=>q(e[c])).join(','))].join('\n')}

global.DBMLogEngine={RULES,detectFormat,parseRows,normalize,analyzeLogs,exportCsv};
})(typeof window!=='undefined'?window:globalThis);
