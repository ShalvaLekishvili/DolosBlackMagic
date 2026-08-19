import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const ctx={globalThis:null,console,Date,JSON,Map,Set,Number,Array,String,Object,RegExp,Math};ctx.globalThis=ctx;vm.createContext(ctx);
for(const file of ['site/log-engine.js','site/wazuh-adapter.js','site/log-normalize-fixes.js'])vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file});
const L=ctx.DBMLogEngine;
let passed=0;
const test=(name,fn)=>{fn();passed++;console.log('✓',name)};

const win4625={
  timestamp:'2026-08-19T12:00:01+0400',
  rule:{level:5,description:'Windows Logon Failure',id:'60122',groups:['windows','authentication_failed']},
  agent:{id:'001',name:'WIN-CLIENT-01',ip:'10.0.0.25'},
  manager:{name:'wazuh-manager'},
  decoder:{name:'windows_eventchannel'},
  location:'EventChannel',
  data:{win:{
    system:{providerName:'Microsoft-Windows-Security-Auditing',eventID:'4625',systemTime:'2026-08-19T08:00:01.000Z',channel:'Security',computer:'WIN-CLIENT-01',severityValue:'AUDIT_FAILURE',message:'An account failed to log on.'},
    eventdata:{targetUserName:'administrator',targetDomainName:'CORP',ipAddress:'203.0.113.44',ipPort:'51234',processName:'C:\\Windows\\System32\\winlogon.exe'}
  }}
};

test('normalizes direct Wazuh Windows alert into canonical fields',()=>{
  const r=L.analyzeLogs(JSON.stringify(win4625));
  assert.equal(r.summary.vendor,'wazuh');
  assert.equal(r.summary.wazuh.recognizedRecords,1);
  const e=r.events[0];
  assert.equal(e.eventId,'4625');
  assert.equal(e.timestamp,'2026-08-19T08:00:01.000Z');
  assert.equal(e.host,'WIN-CLIENT-01');
  assert.equal(e.user,'administrator');
  assert.equal(e.domain,'CORP');
  assert.equal(e.srcIp,'203.0.113.44');
  assert.equal(e.srcPort,'51234');
  assert.equal(e.provider,'Microsoft-Windows-Security-Auditing');
  assert.equal(e.channel,'Security');
  assert.equal(e.source,'windows_eventchannel');
  assert.ok(r.findings.some(f=>f.ruleId==='WIN-4625'));
});

test('unwraps Wazuh Indexer/OpenSearch hits.hits _source exports',()=>{
  const payload={hits:{hits:[{_index:'wazuh-alerts-4.x-2026.08.19',_id:'abc',_source:win4625}]}};
  const r=L.analyzeLogs(JSON.stringify(payload));
  assert.equal(r.events.length,1);
  assert.equal(r.events[0].eventId,'4625');
  assert.equal(r.summary.wazuh.wrapper,'opensearch-hits');
});

test('unwraps Wazuh API affected_items and preserves Linux auth context',()=>{
  const alert={timestamp:'2026-08-19T08:01:00Z',rule:{level:5,id:'5716',description:'sshd: authentication failed.',groups:['syslog','sshd','authentication_failed']},agent:{id:'002',name:'linux01',ip:'10.0.0.30'},decoder:{name:'sshd'},location:'/var/log/auth.log',full_log:'Aug 19 12:01:00 linux01 sshd[123]: Failed password for invalid user root from 198.51.100.8 port 44444 ssh2',data:{srcip:'198.51.100.8',srcport:'44444',srcuser:'root'}};
  const r=L.analyzeLogs(JSON.stringify({data:{affected_items:[alert],total_affected_items:1}}));
  assert.equal(r.events.length,1);
  assert.equal(r.events[0].host,'linux01');
  assert.equal(r.events[0].srcIp,'198.51.100.8');
  assert.equal(r.events[0].user,'root');
  assert.match(r.events[0].message,/Failed password/);
  assert.ok(r.findings.some(f=>f.ruleId==='LINUX-SSH-FAIL'));
  assert.equal(r.summary.wazuh.wrapper,'wazuh-api-affected-items');
});

test('does not confuse Wazuh rule id with Windows event id',()=>{
  const alert={timestamp:'2026-08-19T08:02:00Z',rule:{level:3,id:'5710',description:'sshd message'},agent:{id:'2',name:'linux01'},decoder:{name:'sshd'},full_log:'sshd session message'};
  const r=L.analyzeLogs(JSON.stringify(alert));
  assert.equal(r.events[0].eventId,'');
  assert.notEqual(r.events[0].eventId,'5710');
});

console.log(`Wazuh tests passed: ${passed}/4`);
