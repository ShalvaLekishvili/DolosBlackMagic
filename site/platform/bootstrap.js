(function(global){
'use strict';
const P=global.DBMPlatform=global.DBMPlatform||{};
const bus=P.bus;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
let controller=null;

function status(msg,error=false){
  const el=$('#logStatus');
  if(el){el.textContent=msg;el.classList.toggle('error',error)}
}

function renderStream(result){
  global.DBMState=global.DBMState||{};
  global.DBMState.logResult=result;
  const s=result.summary||{},p=s.parse||{};
  if($('#logFormat'))$('#logFormat').textContent=String(s.format||'stream').toUpperCase();
  if($('#logEvents'))$('#logEvents').textContent=s.total||result.events.length;
  if($('#logFindings'))$('#logFindings').textContent=result.findings.length;
  if($('#logCritical'))$('#logCritical').textContent=result.findings.filter(f=>['critical','high'].includes(f.severity)).length;
  if($('#logParsed'))$('#logParsed').textContent=p.parsed||0;
  if($('#logPartial'))$('#logPartial').textContent=p.partial||0;
  if($('#logMalformed'))$('#logMalformed').textContent=p.malformed||0;
  if($('#logDropped'))$('#logDropped').textContent=p.dropped||0;
  const list=$('#findingList');
  if(list)list.innerHTML=result.findings.length
    ?result.findings.slice(0,120).map((f,i)=>`<button class="log-finding sev-${esc(f.severity)}" data-stream-finding="${i}"><div><span class="severity-pill ${esc(f.severity)}">${esc(f.severity)}</span><b>${esc(f.name)}</b></div><small>${esc(f.ruleId)} · ${esc(f.confidence||'unknown')} confidence · ${(f.eventIds||[]).length} evidence event(s)</small></button>`).join('')
    :'<div class="empty"><h3>No detections fired</h3><p>Telemetry remains available for investigation.</p></div>';
  const body=$('#logBody');
  if(body)body.innerHTML=result.events.slice(0,750).map(e=>`<tr><td>${esc((e.timestamp||'—').replace('T',' ').replace('Z',''))}</td><td><span class="severity-pill ${esc(e.severity)}">${esc(e.severity)}</span></td><td>${esc(e.source)}</td><td>${esc(e.stableId||e.eventId||e.id)}</td><td>${esc(e.host||'—')}<small>${esc(e.user||'')}</small></td><td><code>${esc(e.srcIp||'—')} → ${esc(e.dstIp||'—')}</code></td><td class="message-cell">${esc(String(e.message||'').slice(0,600))}</td></tr>`).join('');
  if($('#logShown'))$('#logShown').textContent=`${result.events.length} events · first ${Math.min(750,result.events.length)} rendered`;
  $('#logWorkspace')?.classList.remove('hidden');
  window.dispatchEvent(new CustomEvent('dbm:log-analysis',{detail:{result,mode:s.streaming?'stream':s.persisted?'vault':'compatibility',sourceName:s.sourceName||''}}));
  bus?.emit('telemetry:loaded',result,{remember:true});
  const inv=P.investigations?.active?.();
  if(inv&&s.sourceName)P.investigations.addSource(inv.id,{name:s.sourceName,kind:'telemetry',format:s.format||'stream',retention:s.persisted?'indexeddb':'ephemeral'});
}

async function compatibilityAnalyze(file,reason){
  status(`Reading ${file.name} with the ${reason} parser…`);
  if(file.size>35*1024*1024)throw Error(`${reason} files above 35 MB are not streamed yet; convert large datasets to NDJSON/JSONL or line-oriented telemetry.`);
  const text=await file.text();
  const result=global.DBMLogEngine.analyzeLogs(text);
  result.summary={...(result.summary||{}),sourceName:file.name,streaming:false,parserMode:'full-file'};
  (result.events||[]).forEach((e,i)=>{
    e.stableId=e.stableId||`EVT-${String(i+1).padStart(7,'0')}`;
    e.provenance=e.provenance||{sourceFile:file.name,recordIndex:i+1,lineNumber:null,byteStart:null,byteEnd:null,parser:e.format||result.summary.format||'',rawPreview:typeof e.raw==='string'?e.raw.slice(0,1600):JSON.stringify(e.raw??{}).slice(0,1600)};
  });
  renderStream(result);
  status(`${reason} analysis complete · ${result.events.length.toLocaleString()} events · full-file compatibility parser`);
}

async function chooseMode(file){
  const name=(file.name||'').toLowerCase();
  if(name.endsWith('.csv'))return'csv';
  if(name.endsWith('.json')&&!name.endsWith('.jsonl'))return'json';
  const head=await file.slice(0,65536).text();
  const trimmed=head.trimStart();
  if(trimmed.startsWith('[')||trimmed.startsWith('{')){
    if(!head.includes('\n')||trimmed.startsWith('['))return'json';
  }
  if(/^[^\n]+,[^\n]+\n/.test(head)&&/(time|date|timestamp|event|message|source|host|user|process)/i.test(head.split(/\r?\n/,1)[0]))return'csv';
  return'stream';
}

async function analyzeFile(file){
  if(!P.streaming||!file)return;
  controller?.abort();
  controller=new AbortController();
  const cancel=$('#cancelLogs'),analyze=$('#analyzeLogs');
  if(cancel){cancel.classList.remove('hidden');cancel.onclick=()=>controller.abort()}
  if(analyze)analyze.disabled=true;
  try{
    const mode=await chooseMode(file);
    if(mode!=='stream'){await compatibilityAnalyze(file,mode.toUpperCase());return}
    status(`Streaming ${file.name} locally…`);
    const {result,summary}=await P.streaming.analyzeFile(file,{signal:controller.signal,onProgress:m=>{
      if(m.totalBytes){
        const pct=Math.min(100,Math.round((m.bytesProcessed/m.totalBytes)*100));
        status(`${m.stage==='reading'?'Reading':'Parsing'} ${file.name}: ${m.bytesProcessed.toLocaleString()} / ${m.totalBytes.toLocaleString()} bytes (${pct}%) · ${m.recordsProcessed||0} records`);
      }
    }});
    result.summary={...(result.summary||{}),sourceName:file.name,streaming:true,stream:summary};
    renderStream(result);
    status(`Streaming complete · ${summary.recordsProcessed.toLocaleString()} records · ${summary.malformed} malformed · ${summary.dropped} dropped · ${summary.elapsedMs} ms`);
  }catch(e){
    if(e.name==='AbortError')status('Analysis cancelled. No partial investigation result was committed.');
    else{console.error(e);status(`Analysis failed safely: ${e.message}`,true)}
  }finally{
    if(cancel)cancel.classList.add('hidden');
    if(analyze)analyze.disabled=false;
    controller=null;
  }
}

function enhanceStreaming(){
  const input=$('#logFile'),drop=$('#logDrop');
  if(!input)return;
  input.onchange=e=>analyzeFile(e.target.files?.[0]);
  if(drop)drop.ondrop=e=>{e.preventDefault();drop.classList.remove('drag');analyzeFile(e.dataTransfer?.files?.[0])};
}

function bridgeLegacy(){
  window.addEventListener('dbm:log-analysis',e=>{
    const r=e.detail?.result;
    if(!r)return;
    bus?.emit('telemetry:loaded',r,{remember:true});
    const inv=P.investigations?.active?.();
    if(!inv)return;
    (r.findings||[]).forEach(f=>P.investigations.addFinding(inv.id,f));
    const entityBatch=new Map();
    for(const ev of (r.events||[]).slice(0,10000)){
      for(const [type,value] of [['host',ev.host],['user',ev.user],['ip',ev.srcIp],['ip',ev.dstIp],['process',ev.process],['domain',ev.domain],['url',ev.url]]){
        if(!value)continue;
        const key=`${type}:${value}`;
        const prior=entityBatch.get(key)||{type,value,count:0,firstSeen:ev.timestamp,lastSeen:ev.timestamp};
        prior.count++;
        if(ev.timestamp){
          if(!prior.firstSeen||ev.timestamp<prior.firstSeen)prior.firstSeen=ev.timestamp;
          if(!prior.lastSeen||ev.timestamp>prior.lastSeen)prior.lastSeen=ev.timestamp;
        }
        entityBatch.set(key,prior);
      }
    }
    for(const item of entityBatch.values())P.investigations.addEntity(inv.id,item.type,item.value,{firstSeen:item.firstSeen,lastSeen:item.lastSeen});
  });
  window.addEventListener('dbm:case-opened',e=>bus?.emit('artifact:opened',e.detail,{remember:true}));
}

function init(){
  const tasks=[['legacy bridge',bridgeLegacy],['streaming',enhanceStreaming]];
  for(const [name,fn] of tasks)try{fn()}catch(e){console.error(`DolosBlackMagic bootstrap: ${name} failed`,e)}
  bus?.emit('platform:ready',{version:'0.8.0',at:new Date().toISOString()},{remember:true});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
P.bootstrap={init,analyzeFile,chooseMode,renderStream,status};
})(window);
