import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const store=new Map();const localStorage={getItem:k=>store.has(k)?store.get(k):null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k),clear:()=>store.clear()};
const context={console,localStorage,performance,structuredClone,Date,Math,JSON,Map,Set,Array,String,Number,RegExp,Error};context.window=context;vm.createContext(context);
for(const file of ['site/platform/investigation-engine.js','site/platform/detection-v3.js'])vm.runInContext(fs.readFileSync(file,'utf8'),context,{filename:file});
const I=context.DBMPlatform.investigations,D=context.DBMPlatform.detectionsV3;
{
 const inv=I.create({title:'Case A'});assert.equal(I.active().id,inv.id);I.addSource(inv.id,{name:'security.jsonl',format:'ndjson'});I.bookmarkEvent(inv.id,{stableId:'EVT-0000001',timestamp:'2026-08-19T10:00:00Z',message:'failed logon',host:'WS01'},{sourceFile:'security.jsonl',recordIndex:1,lineNumber:1,parser:'ndjson',rawPreview:'{"event":4625}'});I.addEntity(inv.id,'host','WS01',{timestamp:'2026-08-19T10:00:00Z'});const saved=I.get(inv.id);assert.equal(saved.dataSources.length,1);assert.equal(saved.bookmarks[0].provenance.recordIndex,1);assert.equal(saved.entities[0].value,'WS01');const snap=I.snapshot();assert.equal(snap.appVersion,'0.8.0');assert.equal(I.validateSnapshot(snap).valid,true);assert.equal(I.validateSnapshot({schemaVersion:99,investigations:[]}).valid,false);
}
{
 const inv=I.active();I.addSource(inv.id,{id:'SRC-DS-1',name:'saved.ndjson',format:'ndjson',retention:'indexeddb'});I.addSource(inv.id,{name:'saved.ndjson',format:'ndjson',retention:'indexeddb'});const saved=I.get(inv.id);assert.equal(saved.dataSources.filter(x=>x.name==='saved.ndjson'&&x.retention==='indexeddb').length,1);
}
{
 const events=[
  {id:1,stableId:'EVT-1',timestamp:'2026-08-19T10:00:00Z',eventId:'4625',srcIp:'203.0.113.10',user:'alice',message:'failed'},
  {id:2,stableId:'EVT-2',timestamp:'2026-08-19T10:00:30Z',eventId:'4625',srcIp:'203.0.113.10',user:'bob',message:'failed'},
  {id:3,stableId:'EVT-3',timestamp:'2026-08-19T10:01:00Z',eventId:'4625',srcIp:'203.0.113.10',user:'carol',message:'failed'}
 ];const r=D.runRule(D.builtins[0],events);assert.equal(r.valid,true);assert.equal(r.findings.length,1);assert.equal(r.findings[0].observed,3);assert.equal(r.findings[0].group,'203.0.113.10');
}
{
 const rule={id:'SEQ',name:'Sequence',sequence:{windowMs:60000,groupBy:['host'],stages:[{field:'eventId',op:'equals',value:'1'},{field:'eventId',op:'equals',value:'2'}]}};const events=[{id:1,timestamp:'2026-08-19T10:00:00Z',host:'A',eventId:'1'},{id:2,timestamp:'2026-08-19T10:00:20Z',host:'A',eventId:'2'}];assert.equal(D.runRule(rule,events).findings.length,1);assert.equal(D.validateRule({...rule,sequence:{windowMs:1,stages:[]}}).valid,false);assert.equal(D.validateRule({id:'R',name:'unsafe',condition:{field:'message',op:'regex',value:'(a+)+$'}}).valid,false);
}
console.log('Platform tests passed');
