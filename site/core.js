(function(global){
  'use strict';

  const suspiciousPatterns = [
    {name:'PowerShell encoded command', re:/powershell(?:\.exe)?[^\n\r]*\s-(?:enc|encodedcommand)\b/i, score:30, mitre:['T1059.001','T1027']},
    {name:'Download cradle', re:/(?:DownloadString|Invoke-WebRequest|iwr\s+https?:\/\/|curl\s+https?:\/\/|wget\s+https?:\/\/)/i, score:24, mitre:['T1105']},
    {name:'Living-off-the-land execution', re:/\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|wmic)(?:\.exe)?\b/i, score:18, mitre:['T1218']},
    {name:'Credential access indicator', re:/\b(?:lsass|sekurlsa|mimikatz|sam\s+save|ntds\.dit)\b/i, score:35, mitre:['T1003']},
    {name:'Persistence indicator', re:/\b(?:schtasks|sc\.exe\s+create|CurrentVersion\\Run|Startup\\|New-Service)\b/i, score:22, mitre:['T1053','T1543','T1060']},
    {name:'Obfuscation', re:/(?:FromBase64String|Char\(|-join|`[A-Za-z]|\^\^|\$\{[^}]+\})/i, score:14, mitre:['T1027']},
    {name:'Potential destructive behavior', re:/\b(?:vssadmin\s+delete|wbadmin\s+delete|bcdedit|cipher\s+\/w|Remove-Item\s+-Recurse)\b/i, score:35, mitre:['T1490','T1485']}
  ];

  function toUint8(input){
    if(input instanceof Uint8Array) return input;
    if(input instanceof ArrayBuffer) return new Uint8Array(input);
    if(typeof input === 'string') return new TextEncoder().encode(input);
    return new Uint8Array();
  }

  async function digestHex(input, algo='SHA-256'){
    const data=toUint8(input);
    const hash=await crypto.subtle.digest(algo,data);
    return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  function shannonEntropy(bytes){
    const arr=toUint8(bytes); if(!arr.length) return 0;
    const freq=new Array(256).fill(0); for(const b of arr) freq[b]++;
    let e=0; for(const n of freq){ if(!n) continue; const p=n/arr.length; e-=p*Math.log2(p); }
    return Number(e.toFixed(3));
  }

  function detectType(bytes,name=''){
    const b=toUint8(bytes); const n=(name||'').toLowerCase();
    const starts=(...vals)=>vals.every((v,i)=>b[i]===v);
    if(starts(0x4d,0x5a)) return 'Windows PE';
    if(starts(0x7f,0x45,0x4c,0x46)) return 'ELF binary';
    if(starts(0x50,0x4b,0x03,0x04)) return /\.(docx|xlsx|pptx)$/i.test(n)?'Office Open XML':'ZIP archive';
    if(starts(0x25,0x50,0x44,0x46)) return 'PDF document';
    if(starts(0x89,0x50,0x4e,0x47)) return 'PNG image';
    if(starts(0xff,0xd8,0xff)) return 'JPEG image';
    if(/\.(ps1|psm1)$/i.test(n)) return 'PowerShell script';
    if(/\.(js|mjs|cjs)$/i.test(n)) return 'JavaScript';
    if(/\.(bat|cmd)$/i.test(n)) return 'Batch script';
    if(/\.(json|ndjson|jsonl)$/i.test(n)) return 'JSON / NDJSON';
    return 'Unknown / text';
  }

  function printableStrings(bytes,min=5,limit=150){
    const arr=toUint8(bytes); const out=[]; let s='';
    const flush=()=>{ if(s.length>=min) out.push(s); s=''; };
    for(const b of arr){ if(b>=32&&b<=126) s+=String.fromCharCode(b); else flush(); if(out.length>=limit) break; }
    flush(); return out.slice(0,limit);
  }

  function normalizeText(text=''){ return String(text).replace(/\u0000/g,'').trim(); }

  function defang(v=''){ return v.replace(/^https?:\/\//i,m=>m.replace('http','hxxp')).replace(/\./g,'[.]'); }

  function extractIOCs(text=''){
    const src=String(text); const found=[]; const seen=new Set();
    const push=(type,value)=>{ const key=type+'|'+value.toLowerCase(); if(!seen.has(key)){ seen.add(key); found.push({type,value,defanged:defang(value)}); } };
    const urlRe=/\bhttps?:\/\/[\w.-]+(?::\d{1,5})?(?:\/[\w\-./?%&=+#:@~]*)?/gi;
    const emailRe=/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
    const hashRe=/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
    const ipRe=/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
    const domainRe=/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|de|uk|ge|info|biz|xyz|top|online|site|cloud|app|dev)\b/gi;
    for(const m of src.match(urlRe)||[]) push('URL',m.replace(/[),.;]+$/,''));
    for(const m of src.match(emailRe)||[]) push('Email',m);
    for(const m of src.match(hashRe)||[]) push(m.length===64?'SHA-256':m.length===40?'SHA-1':'MD5',m);
    for(const m of src.match(ipRe)||[]) push('IPv4',m);
    for(const m of src.match(domainRe)||[]) if(!found.some(x=>x.type==='URL'&&x.value.includes(m))) push('Domain',m.toLowerCase());
    return found;
  }

  function scoreSuspicion(text=''){
    const hits=[]; const mitre=new Set(); let score=0;
    for(const p of suspiciousPatterns){ if(p.re.test(text)){ hits.push({name:p.name,score:p.score,mitre:p.mitre}); score+=p.score; p.mitre.forEach(x=>mitre.add(x)); } }
    score=Math.min(100,score);
    const severity=score>=75?'Critical':score>=50?'High':score>=25?'Medium':score>0?'Low':'Informational';
    return {score,severity,hits,mitre:[...mitre]};
  }

  function parseJsonEvents(text=''){
    const src=String(text).trim(); if(!src) return [];
    let rows=[];
    try{ const p=JSON.parse(src); rows=Array.isArray(p)?p:[p]; }
    catch{ rows=src.split(/\r?\n/).map(l=>l.trim()).filter(Boolean).map(l=>{try{return JSON.parse(l)}catch{return null}}).filter(Boolean); }
    const get=(o,paths)=>{ for(const p of paths){ let v=o; for(const k of p.split('.')) v=v&&v[k]; if(v!==undefined&&v!==null) return v; } };
    return rows.map((o,i)=>{
      const t=get(o,['timestamp','@timestamp','time','event.created','event.ingested','win.system.systemTime','data.timestamp'])||new Date(Date.now()+i).toISOString();
      const title=get(o,['message','event.action','rule.description','win.system.message','data.message','action'])||`Event ${i+1}`;
      const host=get(o,['host.name','agent.name','computer_name','win.system.computer','hostname'])||'unknown-host';
      return {id:i+1,time:String(t),title:String(title).slice(0,240),host:String(host),raw:o};
    }).sort((a,b)=>new Date(a.time)-new Date(b.time));
  }

  function decodeBase64Layers(input='',maxLayers=5){
    let current=String(input).trim(); const layers=[];
    for(let i=0;i<maxLayers;i++){
      const candidate=current.replace(/\s+/g,'');
      if(!/^[A-Za-z0-9+/=_-]{8,}$/.test(candidate)) break;
      try{
        const normalized=candidate.replace(/-/g,'+').replace(/_/g,'/');
        const binary=atob(normalized); const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
        let decoded;
        try{ decoded=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
        catch{ decoded=[...bytes].map(b=>String.fromCharCode(b)).join(''); }
        if(/\u0000/.test(decoded)) decoded=decoded.replace(/\u0000/g,'');
        layers.push({layer:i+1,inputLength:current.length,output:decoded});
        if(decoded===current||decoded.length===0) break; current=decoded.trim();
      }catch{ break; }
    }
    return layers;
  }

  function buildGraph({name='Artifact',iocs=[],suspicion={hits:[]},events=[]}={}){
    const nodes=[{id:'artifact',label:name,type:'artifact'}]; const edges=[];
    iocs.slice(0,18).forEach((ioc,i)=>{ const id='ioc'+i; nodes.push({id,label:ioc.value,type:ioc.type}); edges.push({from:'artifact',to:id,label:'indicator'}); });
    (suspicion.hits||[]).slice(0,10).forEach((h,i)=>{ const id='beh'+i; nodes.push({id,label:h.name,type:'behavior'}); edges.push({from:'artifact',to:id,label:'behavior'}); });
    events.slice(0,8).forEach((e,i)=>{ const id='evt'+i; nodes.push({id,label:e.title,type:'event'}); edges.push({from:'artifact',to:id,label:e.host}); });
    return {nodes,edges};
  }

  function reportMarkdown(caseData){
    const c=caseData||{}; const a=c.analysis||{}; const s=a.suspicion||{};
    const lines=[`# DolosBlackMagic Investigation Report`,``,`**Case:** ${c.title||'Untitled'}`,`**Created:** ${c.createdAt||''}`,`**Risk:** ${s.severity||'Informational'} (${s.score||0}/100)`,``,`## Executive Summary`,c.summary||`Static browser-side analysis identified ${a.iocs?.length||0} indicators and ${s.hits?.length||0} suspicious behavior patterns.`,``,`## Artifact`,`- Name: ${a.name||'Text input'}`,`- Type: ${a.type||'Unknown'}`,`- Size: ${a.size||0} bytes`,`- SHA-256: ${a.sha256||'n/a'}`,`- SHA-1: ${a.sha1||'n/a'}`,`- Entropy: ${a.entropy??'n/a'}`,``,`## Findings`];
    if(s.hits?.length) s.hits.forEach(x=>lines.push(`- **${x.name}** (+${x.score}) — ${x.mitre.join(', ')}`)); else lines.push('- No suspicious heuristic matches.');
    lines.push('','## Indicators of Compromise'); if(a.iocs?.length) a.iocs.forEach(x=>lines.push(`- ${x.type}: \`${x.defanged}\``)); else lines.push('- None extracted.');
    lines.push('','## MITRE ATT&CK'); if(s.mitre?.length) s.mitre.forEach(x=>lines.push(`- ${x}`)); else lines.push('- No mapped techniques.');
    lines.push('','## Timeline'); if(a.events?.length) a.events.forEach(e=>lines.push(`- ${e.time} — ${e.title} (${e.host})`)); else lines.push('- No structured events parsed.');
    lines.push('','---','Generated locally by DolosBlackMagic. No artifact bytes were uploaded by the core static application.');
    return lines.join('\n');
  }

  async function analyzeInput({name='Text input',bytes=null,text=''}){
    const data=bytes?toUint8(bytes):toUint8(text); let analysisText=normalizeText(text);
    if(!analysisText && data.length){ analysisText=printableStrings(data,4,250).join('\n'); }
    const [sha256,sha1]=await Promise.all([digestHex(data,'SHA-256'),digestHex(data,'SHA-1')]);
    const iocs=extractIOCs(analysisText); const suspicion=scoreSuspicion(analysisText); const events=parseJsonEvents(analysisText);
    return {name,size:data.length,type:detectType(data,name),sha256,sha1,entropy:shannonEntropy(data),strings:printableStrings(data),iocs,suspicion,events,graph:buildGraph({name,iocs,suspicion,events}),textPreview:analysisText.slice(0,12000)};
  }

  global.DBMCore={digestHex,shannonEntropy,detectType,printableStrings,extractIOCs,scoreSuspicion,parseJsonEvents,decodeBase64Layers,buildGraph,reportMarkdown,analyzeInput,defang};
})(typeof window!=='undefined'?window:globalThis);
