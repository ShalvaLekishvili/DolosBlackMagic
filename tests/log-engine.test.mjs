import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const code=fs.readFileSync(new URL('../site/log-engine.js',import.meta.url),'utf8');
const ctx={globalThis:{},console,Date,JSON,Map,Set};ctx.globalThis=ctx;vm.createContext(ctx);vm.runInContext(code,ctx);
const L=ctx.DBMLogEngine;
let passed=0;
function test(name,fn){try{fn();passed++;console.log('✓',name)}catch(e){console.error('✗',name);throw e}}

test('detects supported formats',()=>{
 assert.equal(L.detectFormat('[{"message":"x"}]'),'json');
 assert.equal(L.detectFormat('{"message":"x"}\n{"message":"y"}'),'ndjson');
 assert.equal(L.detectFormat('timestamp,host,message\n2026-08-18T10:00:00Z,a,ok'),'csv');
 assert.equal(L.detectFormat('CEF:0|Vendor|Product|1|100|Alert|8|src=1.2.3.4'),'cef');
 assert.equal(L.detectFormat('<34>2026-08-18T10:00:00Z host sshd[1]: Failed password'),'syslog');
});

test('normalizes heterogeneous JSON fields',()=>{
 const r=L.analyzeLogs(JSON.stringify({
  '@timestamp':'2026-08-18T10:00:00Z',
  event:{code:4625,module:'windows'},host:{name:'DC01'},source:{ip:'203.0.113.4'},
  user:{name:'admin'},message:'An account failed to log on'
 }));
 assert.equal(r.events.length,1);assert.equal(r.events[0].eventId,'4625');assert.equal(r.events[0].host,'DC01');assert.equal(r.events[0].srcIp,'203.0.113.4');
 assert.ok(r.findings.some(f=>f.ruleId==='WIN-4625'));
});

test('detects encoded PowerShell and audit-log clearing',()=>{
 const rows=[
  {'@timestamp':'2026-08-18T10:00:00Z',event:{code:4688},process:{name:'powershell.exe',command_line:'powershell.exe -EncodedCommand SQBFAFgA'},message:'new process'},
  {'@timestamp':'2026-08-18T10:01:00Z',event:{code:1102},message:'The audit log was cleared'}
 ];
 const r=L.analyzeLogs(JSON.stringify(rows));
 assert.ok(r.findings.some(f=>f.ruleId==='WIN-4688-PS'));assert.ok(r.findings.some(f=>f.ruleId==='WIN-1102'));
});

test('correlates repeated authentication failures',()=>{
 const rows=Array.from({length:6},(_,i)=>({'@timestamp':`2026-08-18T10:0${i}:00Z`,event:{code:4625},source:{ip:'198.51.100.10'},user:{name:'administrator'},message:'failed logon'}));
 const r=L.analyzeLogs(JSON.stringify(rows));assert.ok(r.findings.some(f=>f.ruleId==='CORR-BRUTEFORCE'&&f.eventIds.length>=5));
});

test('correlates multi-port connection activity',()=>{
 const rows=Array.from({length:12},(_,i)=>({'@timestamp':`2026-08-18T10:00:${String(i).padStart(2,'0')}Z`,source:{ip:'192.0.2.50',port:44000+i},destination:{ip:'10.0.0.9',port:20+i},event:{action:'connection'},message:'network connection'}));
 const r=L.analyzeLogs(JSON.stringify(rows));assert.ok(r.findings.some(f=>f.ruleId==='CORR-PORTSCAN'));
});

console.log(`BlackLog tests passed: ${passed}/5`);
