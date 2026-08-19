import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const ctx={window:null,globalThis:null,console,Date,JSON,Map,Set,Number,Array,String,Object,RegExp,Math,performance:{now:()=>0}};ctx.window=ctx;ctx.globalThis=ctx;vm.createContext(ctx);
for(const file of ['site/log-engine.js','site/wazuh-adapter.js','site/log-normalize-fixes.js','site/platform/detection-v3.js','site/platform/detection-pipeline.js'])vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file});
const L=ctx.DBMLogEngine,P=ctx.DBMPlatform.detectionPipeline;
function mk(i,over={}){
 return {
  timestamp:`2026-08-19T08:00:${String(i).padStart(2,'0')}Z`,
  rule:{level:5,id:'60122',description:'Logon Failure - Unknown user or bad password',groups:['windows','windows_security','authentication_failed']},
  agent:{id:'056',name:'SERVER01',ip:'10.22.42.11'},decoder:{name:'windows_eventchannel'},location:'EventChannel',
  data:{win:{
   system:{eventID:'4625',systemTime:`2026-08-19T08:00:${String(i).padStart(2,'0')}Z`,channel:'Security',computer:'SERVER01',providerName:'Microsoft-Windows-Security-Auditing',message:'An account failed to log on.'},
   eventdata:{targetUserName:'administrator',subjectUserName:'RDWebAccess',subjectDomainName:'IIS APPPOOL',logonType:'3',processName:'C:\\Windows\\System32\\inetsrv\\w3wp.exe',status:'0xc000006d',subStatus:'0xc000006a',...over}
  }}
 };
}
{
 const events=Array.from({length:5},(_,i)=>mk(i,{ipAddress:'198.51.100.10',ipPort:String(50000+i)}));
 const r=P.apply(L.analyzeLogs(JSON.stringify(events)));
 assert.ok(r.findings.some(f=>f.ruleId==='CORR-AUTH-GUESSING'));
}
{
 const users=['alice','bob','carol'];
 const events=users.map((u,i)=>mk(i,{targetUserName:u,ipAddress:'203.0.113.10'}));
 const r=P.apply(L.analyzeLogs(JSON.stringify(events)));
 assert.ok(r.findings.some(f=>f.ruleId==='CORR-AUTH-SPRAY'));
}
{
 const events=Array.from({length:5},(_,i)=>mk(i));
 const r=P.apply(L.analyzeLogs(JSON.stringify(events)));
 assert.ok(r.findings.some(f=>f.ruleId==='CORR-LOCAL-AUTH-FAIL-BURST'));
 assert.equal(r.events[0].srcIp,'');
 assert.equal(r.events[0].targetUser,'administrator');
 assert.equal(r.events[0].subjectUser,'RDWebAccess');
 assert.equal(r.events[0].logonType,'3');
}
console.log('Authentication detection tests passed');
