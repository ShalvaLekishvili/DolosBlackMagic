import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const code=fs.readFileSync(new URL('../site/core.js',import.meta.url),'utf8');
const ctx={crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,console,atob:globalThis.atob};ctx.globalThis=ctx;vm.createContext(ctx);vm.runInContext(code,ctx);const C=ctx.DBMCore;
let pass=0,fail=0;function t(name,fn){try{fn();console.log('✓',name);pass++}catch(e){console.error('✗',name,'\n ',e.message);fail++}}function eq(a,b){if(a!==b)throw new Error(`${a} !== ${b}`)}
t('IOC extraction finds URL/IP/hash',()=>{const x=C.extractIOCs('https://evil.example.com/a 203.0.113.7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');if(!x.some(i=>i.type==='URL'))throw new Error('URL missing');if(!x.some(i=>i.type==='IPv4'))throw new Error('IP missing');if(!x.some(i=>i.type==='SHA-256'))throw new Error('hash missing')});
t('Suspicion scoring detects encoded PowerShell',()=>{const r=C.scoreSuspicion('powershell.exe -EncodedCommand SQBFAFgA');if(r.score<25)throw new Error('score too low');if(!r.mitre.includes('T1059.001'))throw new Error('MITRE missing')});
t('JSON event parsing normalizes timestamp',()=>{const r=C.parseJsonEvents(JSON.stringify([{timestamp:'2026-08-18T10:00:00Z',message:'hello',hostname:'lab'}]));eq(r.length,1);eq(r[0].host,'lab')});
t('Base64 decoder peels a layer',()=>{const r=C.decodeBase64Layers('SGVsbG8gV29ybGQ=');eq(r[0].output,'Hello World')});
t('File signature detects PE',()=>{eq(C.detectType(new Uint8Array([0x4d,0x5a,0,0]),'x.exe'),'Windows PE')});
console.log(`\n${pass} passed, ${fail} failed`);if(fail)process.exit(1);
