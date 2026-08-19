import fs from 'node:fs';
import vm from 'node:vm';
const root=new URL('../site/',import.meta.url);
const pkg=JSON.parse(fs.readFileSync(new URL('../package.json',import.meta.url),'utf8'));
const release=pkg.version;
const required=['index.html','app.css','log.css','soc.css','ops.css','v05.css','v06-ui.css','platform/platform.css','core.js','log-engine.js','log-worker.js','soc-engine.js','ops-engine.js','security-runtime.js','platform/app-bus.js','platform/investigation-engine.js','platform/detection-v3.js','platform/detection-pipeline.js','platform/workspace-store.js','platform/log-stream-client.js','platform/log-stream-worker.js','platform/event-explorer-v2.js','platform/investigation-ui.js','platform/global-search.js','platform/bootstrap.js','platform/dataset-vault-ui.js','app.js','log-ui.js','soc-ui.js','ops-ui.js','ui-hardening.js','dashboard-v06.js','log-normalize-fixes.js','soc-v05-ui.js','favicon.svg','manifest.webmanifest','sw.js'];
let fail=0;const bad=(...x)=>{console.error(...x);fail++};
for(const file of required){const p=new URL(file,root);if(!fs.existsSync(p))bad('missing',file);else console.log('ok',file)}
for(const file of required.filter(x=>x.endsWith('.js'))){try{new vm.Script(fs.readFileSync(new URL(file,root),'utf8'),{filename:file})}catch(e){bad('javascript syntax error',file,e.message)}}
const html=fs.readFileSync(new URL('index.html',root),'utf8');
const indexRefs=required.filter(x=>(x.endsWith('.js')||x.endsWith('.css'))&&!['sw.js','log-worker.js','platform/log-stream-worker.js','log-normalize-fixes.js','soc-v05-ui.js'].includes(x));
for(const ref of indexRefs)if(!html.includes(ref))bad('index missing ref',ref);
const ids=[...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m=>m[1]);const dup=[...new Set(ids.filter((id,i)=>ids.indexOf(id)!==i))];if(dup.length)bad('duplicate static ids',dup.join(', '));for(const target of [...html.matchAll(/data-(?:view|jump)=["']([^"']+)["']/g)].map(m=>m[1]))if(!html.includes(`id="view-${target}"`)&&!['logs','soc','ops'].includes(target))bad('missing navigation target',target);
const sw=fs.readFileSync(new URL('sw.js',root),'utf8');for(const ref of required.filter(x=>x!=='sw.js'))if(!sw.includes(`./${ref}`))bad('service worker missing asset',ref);if(!sw.includes(`dbm-${release}`))bad(`PWA cache must derive from package release ${release}`);
const manifest=JSON.parse(fs.readFileSync(new URL('manifest.webmanifest',root),'utf8'));if(!manifest.start_url?.startsWith('./')||!manifest.scope?.startsWith('./'))bad('manifest must remain subpath-safe');
const readme=fs.readFileSync(new URL('../README.md',import.meta.url),'utf8');if(!readme.includes(`version-${release.replaceAll('-','--')}`)&&!readme.includes(`version-${release}`))bad(`README version badge must match ${release}`);if(!readme.includes('ქართული განმარტება'))bad('README must retain Georgian documentation');
const releaseDoc=new URL(`../docs/V${release.split('.').slice(0,2).join('.')}.md`,import.meta.url);if(!fs.existsSync(releaseDoc))bad(`release documentation missing for ${release}`);
const netlify=fs.readFileSync(new URL('../netlify.toml',import.meta.url),'utf8');if(!netlify.includes('Content-Security-Policy'))bad('Netlify CSP missing');if(fail)process.exit(1);console.log(`Static integrity passed for DolosBlackMagic ${release}`);
