import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const store=new Map();const localStorage={getItem:k=>store.has(k)?store.get(k):null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k),clear:()=>store.clear()};
const context={console,localStorage,performance,structuredClone,Date,Math,JSON,Map,Set,Array,String,Number,RegExp,Error};context.window=context;vm.createContext(context);
for(const file of ['site/platform/investigation-engine.js','site/platform/detection-v3.js','site/platform/detection-pipeline.js'])vm.runInContext(fs.readFileSync(file,'utf8'),context,{filename:file});
const I=context.DBMPlatform.investigations,D=context.DBMPlatform.detectionsV3,P=context.DBMPlatform.detectionPipeline;
{
 const inv=I.create({title:'Case A'});assert.equal(I.active().id,inv.id);I.addSource(inv.id,{name:'security.jsonl',format:'ndjson'});I.bookmarkEvent(inv.id,{stableId:'EVT-0000001',timestamp:'2026-08-19T10:00:00Z',message:'failed logon',host:'WS01'},{sourceFile:'security.jsonl',recordIndex:1,lineNumber:1,parser:'ndjson',rawPreview:'{"event":4625}'});I.addEntity(inv.id,'host','WS01',{timestamp:'2026-08-19T10:00:00Z'});const saved=I.get(inv.id);assert.equal(saved.dataSources.length,1);assert.equal(saved.bookmarks[0].provenance.recordIndex,1);assert.equal(saved.entities[0].value,'WS01');assert.equal(I.validateSnapshot(I.snapshot()).valid,true);assert.equal(I.validateSnapshot({schemaVersion:99,investigations:[]}).valid,false);
}
{
 const inv=I.active();I.addSource(inv.id,{id:'SRC-DS-1',name:'saved.ndjson',format:'ndjson',retention:'indexeddb'});I.addSource(inv.id,{name:'saved.ndjson',format:'ndjson',retention:'indexeddb'});const saved=I.get(inv.id);assert.equal(saved.dataSources.filter(x=>x.name==='saved.ndjson'&&x.retention==='indexeddb').length,1);
}
{
 const spray=D.builtins.find(x=>x.id==='CORR-AUTH-SPRAY');const events=[
  {id:1,stableId:'EVT-1',timestamp:'2026-08-19T10:00:00Z',eventId:'4625',srcIp:'203.0.113.10',user:'alice',message:'failed'},
  {id:2,stableId:'EVT-2',timestamp:'2026-08-19T10:00:30Z',eventId:'4625',srcIp:'203.0.113.10',user:'bob',message:'failed'},
  {id:3,stableId:'EVT-3',timestamp:'2026-08-19T10:01:00Z',eventId:'4625',srcIp:'203.0.113.10',user:'carol',message:'failed'}
 ];const r=D.runRule(spray,events);assert.equal(r.valid,true);assert.equal(r.findings.length,1);assert.equal(r.findings[0].observed,3);assert.equal(r.findings[0].group,'203.0.113.10');
}
{
 const spray=D.builtins.find(x=>x.id==='CORR-AUTH-SPRAY');const noSource=[0,1,2].map(i=>({id:i,timestamp:`2026-08-19T10:00:0${i}Z`,eventId:'4625',user:`u${i}`,message:'failed'}));assert.equal(D.runRule(spray,noSource).findings.length,0,'missing group key must not correlate unrelated events');
}
{
 const rule=D.builtins.find(x=>x.id==='CORR-AUTH-SUCCESS-AFTER-FAIL');const base=[0,1,2].map(i=>({id:i+1,stableId:`F${i}`,timestamp:`2026-08-19T10:00:0${i}Z`,eventId:'4625',srcIp:'198.51.100.20',message:'failed password'}));const success={id:4,stableId:'S1',timestamp:'2026-08-19T10:00:05Z',eventId:'4624',srcIp:'198.51.100.20',message:'successful logon'};assert.equal(D.runRule(rule,[...base.slice(0,2),success]).findings.length,0);const r=D.runRule(rule,[...base,success]);assert.equal(r.findings.length,1);assert.equal(r.findings[0].eventIds.length,4);
}
{
 const rule=D.builtins.find(x=>x.id==='CORR-FIREWALL-DENY-SCAN');const events=Array.from({length:10},(_,i)=>({id:i+1,stableId:`D${i}`,timestamp:`2026-08-19T10:00:${String(i).padStart(2,'0')}Z`,srcIp:'192.0.2.9',dstIp:'10.0.0.9',dstPort:String(20+i),action:'deny',message:'blocked'}));const r=D.runRule(rule,events);assert.equal(r.findings.length,1);assert.equal(r.findings[0].observed,10);assert.equal(r.findings[0].distinctField,'dstPort');
}
{
 const rule={id:'SEQ',name:'Sequence',sequence:{windowMs:60000,groupBy:['host'],stages:[{field:'eventId',op:'equals',value:'1'},{field:'eventId',op:'equals',value:'2'}]}};const events=[{id:1,timestamp:'2026-08-19T10:00:00Z',host:'A',eventId:'1'},{id:2,timestamp:'2026-08-19T10:00:20Z',host:'A',eventId:'2'}];assert.equal(D.runRule(rule,events).findings.length,1);assert.equal(D.validateRule({...rule,sequence:{windowMs:1,stages:[]}}).valid,false);assert.equal(D.validateRule({id:'R',name:'unsafe',condition:{field:'message',op:'regex',value:'(a+)+$'}}).valid,false);
}
{
 const result={events:[{id:1,stableId:'E1',timestamp:'2026-08-19T10:00:00Z',eventId:'1102',message:'audit cleared',detections:[]}],findings:[{id:'OLD',ruleId:'WIN-1102',name:'Audit cleared',severity:'critical',confidence:'high',eventIds:['E1'],why:'source rule'}],summary:{}};const merged=P.apply(result);assert.equal(merged.findings[0].kind,'high-confidence');assert.equal(merged.findings[0].sourceEngine,'blacklog');assert.ok(merged.events[0].detections.includes('WIN-1102'));assert.ok(merged.summary.detectionPipeline.total>=1);
}
console.log('Platform tests passed');
