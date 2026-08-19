(function(){'use strict';
const S=window.DBMSOC;if(!S)return;
function regexRisk(value){const s=String(value??'');if(s.length>256)return'pattern-too-long';if(/(?:\([^)]*[+*][^)]*\))[+*{]/.test(s)||/(?:\.\*|\.\+).*(?:\.\*|\.\+)/.test(s))return'nested-or-overlapping-quantifier';try{new RegExp(s,'i');return''}catch{return'invalid-regex'}}
function ruleRisk(rule){for(const c of rule?.conditions||[])if(c.op==='regex'){const risk=regexRisk(c.value);if(risk)return`${risk}:${c.field||'unknown'}`}return''}
const originalSave=S.saveRule.bind(S);S.saveRule=function(rule){const risk=ruleRisk(rule);if(risk)throw Error(`Regex rejected for browser safety: ${risk}`);return originalSave(rule)};
const originalRun=S.runRules.bind(S);S.runRules=function(events,rules){const selected=(rules||S.customRules()).filter(r=>!ruleRisk(r));return originalRun(events,selected)};
const originalTest=S.testRuleAgainstEvents.bind(S);S.testRuleAgainstEvents=function(rule,events){const risk=ruleRisk(rule);if(risk)return{valid:false,errors:[`unsafe-regex:${risk}`],count:0,samples:[]};return originalTest(rule,events)};
const originalSigma=S.parseSigmaDetailed.bind(S);S.parseSigmaDetailed=function(text){const out=originalSigma(text);if(out.rule){const risk=ruleRisk(out.rule);if(risk){S.setRuleLifecycle(out.rule.id,'disabled');out.report={...out.report,status:'partially-translated',unsupported:[...(out.report.unsupported||[]),`unsafe-regex:${risk}`]};out.rule={...out.rule,lifecycle:'disabled',enabled:false,importReport:out.report}}return out};
window.DBMSecurity={regexRisk,ruleRisk};
})();
