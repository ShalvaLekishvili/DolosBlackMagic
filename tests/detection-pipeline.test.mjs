import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const listeners=new Map();
const context={console,Date,Math,JSON,Map,Set,Array,String,Number,RegExp,Error,performance,Promise,DBMState:{}};
context.window=context;
context.addEventListener=(name,fn)=>listeners.set(name,fn);
context.document={getElementById(){return null}};
context.DBMPlatform={bus:{emit(){}}};
vm.createContext(context);
for(const file of ['site/platform/detection-v3.js','site/platform/detection-pipeline.js']){
  vm.runInContext(fs.readFileSync(file,'utf8'),context,{filename:file});
}
const D=context.DBMPlatform.detectionsV3;
const P=context.DBMPlatform.detectionPipeline;
let passed=0;
const test=(name,fn)=>{fn();passed++;console.log('✓',name)};

test('merges v3 correlations into canonical findings and links evidence events',()=>{
  const events=[
    {id:1,stableId:'EVT-1',timestamp:'2026-08-19T10:00:00Z',eventId:'4625',srcIp:'203.0.113.7',user:'alice',message:'failed logon',detections:[]},
    {id:2,stableId:'EVT-2',timestamp:'2026-08-19T10:00:20Z',eventId:'4625',srcIp:'203.0.113.7',user:'bob',message:'failed logon',detections:[]},
    {id:3,stableId:'EVT-3',timestamp:'2026-08-19T10:00:40Z',eventId:'4625',srcIp:'203.0.113.7',user:'carol',message:'failed logon',detections:[]}
  ];
  const result=P.apply({events,findings:[],summary:{}});
  const finding=result.findings.find(f=>f.ruleId==='CORR-AUTH-SPRAY');
  assert.ok(finding);
  assert.equal(finding.sourceEngine,'detection-v3');
  assert.equal(finding.kind,'correlated');
  assert.ok(events.every(e=>e.detections.includes('CORR-AUTH-SPRAY')));
  assert.ok(result.summary.detectionPipeline.v3Added>=1);
  assert.equal(result.summary.detectionPipeline.canonical,true);
  assert.equal(result.summary.findings,result.findings.length);
});

test('deduplicates equivalent rule and evidence combinations',()=>{
  const existing={id:'x',ruleId:'R1',name:'Existing',severity:'medium',confidence:'medium',eventIds:['EVT-1']};
  const result={events:[{stableId:'EVT-1',id:1,timestamp:'2026-08-19T10:00:00Z',message:'x'}],findings:[existing,{...existing,id:'y'}],summary:{}};
  const output=P.apply(result);
  assert.equal(output.findings.filter(f=>f.ruleId==='R1').length,1);
});

test('classifies strong non-correlation findings separately',()=>{
  assert.equal(P.classify({severity:'high',confidence:'high',correlation:false}),'high-confidence');
  assert.equal(P.classify({severity:'medium',confidence:'medium',correlation:false}),'suspicious');
  assert.equal(P.classify({severity:'low',confidence:'low',correlation:false}),'informational');
});

test('repeated-stage sequence requires the configured failure burst',()=>{
  const rule=D.builtins.find(r=>r.id==='CORR-AUTH-SUCCESS-AFTER-FAIL');
  assert.ok(rule);
  const tooFew=[
    {id:1,timestamp:'2026-08-19T10:00:00Z',eventId:'4625',srcIp:'198.51.100.2',message:'failed'},
    {id:2,timestamp:'2026-08-19T10:00:20Z',eventId:'4624',srcIp:'198.51.100.2',message:'success'}
  ];
  assert.equal(D.runRule(rule,tooFew).findings.length,0);
  const enough=[
    {id:1,timestamp:'2026-08-19T10:00:00Z',eventId:'4625',srcIp:'198.51.100.2',message:'failed'},
    {id:2,timestamp:'2026-08-19T10:00:10Z',eventId:'4625',srcIp:'198.51.100.2',message:'failed'},
    {id:3,timestamp:'2026-08-19T10:00:20Z',eventId:'4625',srcIp:'198.51.100.2',message:'failed'},
    {id:4,timestamp:'2026-08-19T10:00:30Z',eventId:'4624',srcIp:'198.51.100.2',message:'success'}
  ];
  assert.equal(D.runRule(rule,enough).findings.length,1);
});

test('missing group key does not correlate unrelated events',()=>{
  const rule={id:'NO-GROUP',name:'No group',condition:{field:'eventId',op:'equals',value:'4625'},threshold:{count:2,windowMs:60000,groupBy:['srcIp']}};
  const events=[
    {id:1,timestamp:'2026-08-19T10:00:00Z',eventId:'4625',message:'failed'},
    {id:2,timestamp:'2026-08-19T10:00:10Z',eventId:'4625',message:'failed'}
  ];
  assert.equal(D.runRule(rule,events).findings.length,0);
});

test('dbm:log-analysis listener applies canonical detections before UI render',()=>{
  const live=Array.from({length:5},(_,i)=>({id:i+1,timestamp:`2026-08-19T10:00:0${i}Z`,eventId:'4625',host:'SERVER01',user:'administrator',logonType:'3',message:'An account failed to log on.',detections:[]}));
  const result={events:live,findings:[],summary:{format:'json',findingSeverity:{}}};
  const listener=listeners.get('dbm:log-analysis');
  assert.equal(typeof listener,'function');
  listener({detail:{result}});
  assert.ok(result.findings.some(f=>f.ruleId==='CORR-NETWORK-LOGON-FAIL-BURST'));
  assert.equal(result.summary.detectionPipeline.canonical,true);
  assert.equal(result.summary.findings,result.findings.length);
  assert.ok(result.events.every(e=>e.detections.includes('CORR-NETWORK-LOGON-FAIL-BURST')));
});

console.log(`Detection pipeline tests passed: ${passed}/6`);
