import assert from 'node:assert/strict';
const mem=new Map();globalThis.localStorage={getItem:k=>mem.has(k)?mem.get(k):null,setItem:(k,v)=>mem.set(k,String(v)),removeItem:k=>mem.delete(k),clear:()=>mem.clear()};globalThis.window=globalThis;
await import('../site/soc-engine.js');await import('../site/security-runtime.js');const S=globalThis.DBMSOC,Sec=globalThis.DBMSecurity;assert.ok(Sec,'security runtime exported');
assert.equal(Sec.regexRisk('powershell.*-enc'),'');assert.match(Sec.regexRisk('(a+)+$'),/nested/);assert.equal(Sec.regexRisk('a'.repeat(300)),'pattern-too-long');
assert.throws(()=>S.saveRule({name:'Unsafe',conditions:[{field:'message',op:'regex',value:'(a+)+$'}]}),/Regex rejected/);
const safe=S.saveRule({name:'Safe regex',conditions:[{field:'message',op:'regex',value:'powershell.*-enc'}]});assert.equal(safe.enabled,true);
const result=S.testRuleAgainstEvents({name:'Unsafe test',conditions:[{field:'message',op:'regex',value:'(x+)+$'}]},[{message:'xxx'}]);assert.equal(result.valid,false);assert.match(result.errors[0],/unsafe-regex/);
console.log('Security runtime tests passed');
