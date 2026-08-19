(function(global){
'use strict';
const P=global.DBMPlatform=global.DBMPlatform||{};
const text=v=>String(v??'');
function summarize(result){
  if(!result||!Array.isArray(result.events))return result;
  if(!result.summary?.detectionPipeline&&P.detectionPipeline?.apply)P.detectionPipeline.apply(result);
  const findings=Array.isArray(result.findings)?result.findings:[];
  const counts={critical:0,high:0,medium:0,low:0,informational:0};
  for(const finding of findings){const sev=text(finding.severity||'informational').toLowerCase();counts[sev]=(counts[sev]||0)+1}
  result.summary={...(result.summary||{}),findings:findings.length,findingSeverity:counts};
  return result;
}
function refreshUi(){
  const result=global.DBMState?.logResult;if(!result)return;
  const findings=Array.isArray(result.findings)?result.findings:[];
  const severity=result.summary?.findingSeverity||{};
  const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=String(value)};
  set('logFindings',findings.length);
  set('logCritical',Number(severity.critical||0)+Number(severity.high||0));
  const base=global.DBMLogEngine?.RULES?.length||0;
  const v3=P.detectionsV3?.builtins?.length||0;
  const ruleCount=document.getElementById('ruleCount');
  if(ruleCount)ruleCount.textContent=`${base+v3} active rules · correlation enabled`;
}
function onAnalysis(event){
  const result=event?.detail?.result||global.DBMState?.logResult;
  if(!result)return;
  summarize(result);
  if(global.DBMState)global.DBMState.logResult=result;
  Promise.resolve().then(refreshUi);
}
global.addEventListener?.('dbm:log-analysis',onAnalysis);
P.liveDetectionBridge={apply:summarize,refreshUi,onAnalysis};
})(typeof window!=='undefined'?window:globalThis);
