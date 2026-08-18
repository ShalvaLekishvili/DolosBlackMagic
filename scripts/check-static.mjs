import fs from 'node:fs';
const root=new URL('../site/',import.meta.url);
const req=['index.html','app.css','core.js','app.js','log-engine.js','log-ui.js','log.css','soc-engine.js','soc-ui.js','soc.css','favicon.svg','manifest.webmanifest','sw.js'];
let fail=0;
for(const f of req){const p=new URL(f,root);if(!fs.existsSync(p)){console.error('missing',f);fail++}else console.log('ok',f)}
const html=fs.readFileSync(new URL('index.html',root),'utf8');
for(const ref of ['app.css','core.js','app.js','log.css','log-engine.js','log-ui.js','soc.css','soc-engine.js','soc-ui.js'])if(!html.includes(ref)){console.error('index missing ref',ref);fail++}
const sw=fs.readFileSync(new URL('sw.js',root),'utf8');
for(const ref of ['log-engine.js','log-ui.js','log.css','soc-engine.js','soc-ui.js','soc.css'])if(!sw.includes(ref)){console.error('service worker missing asset',ref);fail++}
if(fail)process.exit(1);console.log('Static integrity passed');
