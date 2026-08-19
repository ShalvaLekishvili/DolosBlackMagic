import fs from 'node:fs';
const root=new URL('../site/',import.meta.url);
const required=['index.html','app.css','log.css','soc.css','ops.css','v05.css','core.js','log-engine.js','soc-engine.js','ops-engine.js','app.js','log-ui.js','soc-ui.js','ops-ui.js','ui-hardening.js','soc-v05-ui.js','favicon.svg','manifest.webmanifest','sw.js'];
let fail=0;const bad=(...x)=>{console.error(...x);fail++};
for(const file of required){const p=new URL(file,root);if(!fs.existsSync(p))bad('missing',file);else console.log('ok',file)}
const html=fs.readFileSync(new URL('index.html',root),'utf8');
for(const ref of ['app.css','log.css','soc.css','ops.css','v05.css','core.js','log-engine.js','soc-engine.js','ops-engine.js','app.js','log-ui.js','soc-ui.js','ops-ui.js','ui-hardening.js'])if(!html.includes(ref))bad('index missing ref',ref);
const ids=[...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m=>m[1]);const dup=[...new Set(ids.filter((id,i)=>ids.indexOf(id)!==i))];if(dup.length)bad('duplicate static ids',dup.join(', '));
for(const target of [...html.matchAll(/data-(?:view|jump)=["']([^"']+)["']/g)].map(m=>m[1]))if(!html.includes(`id="view-${target}"`)&&!['logs','soc','ops'].includes(target))bad('missing navigation target',target);
const sw=fs.readFileSync(new URL('sw.js',root),'utf8');for(const ref of required.filter(x=>!['sw.js'].includes(x)))if(!sw.includes(`./${ref}`)&&!['favicon.svg','manifest.webmanifest'].includes(ref))bad('service worker missing asset',ref);for(const ref of ['favicon.svg','manifest.webmanifest'])if(!sw.includes(`./${ref}`))bad('service worker missing asset',ref);
if(!/const CACHE='dbm-v6'/.test(sw))bad('unexpected PWA cache version');
const manifest=JSON.parse(fs.readFileSync(new URL('manifest.webmanifest',root),'utf8'));if(!manifest.start_url?.startsWith('./'))bad('manifest start_url must remain subpath-safe');
const pkg=JSON.parse(fs.readFileSync(new URL('../package.json',import.meta.url),'utf8'));if(pkg.version!=='0.5.0')bad('package version must be 0.5.0');
if(fail)process.exit(1);console.log('Static integrity passed');
