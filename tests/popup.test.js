import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs';
import {detect} from '../engine.js';
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.events={};this.value='';this.disabled=false;this.textContent='';}
 append(...items){this.children.push(...items);}replaceChildren(){this.children=[];}addEventListener(type,fn){this.events[type]=fn;}click(){this.events.click?.();}
}
async function setup(url='https://fixture.test/',options={}){
 const ids=['host','status','search','scan','count','export','results','headers','notice','hunt','fresh','auto-hunt','hunt-status','hunt-results'];const els=Object.fromEntries(ids.map(k=>[k,new Element(k)]));
 const target={id:1,url};const calls=[];
 const context=vm.createContext({document:{getElementById:id=>els[id],createElement:tag=>new Element(tag)},URL,Blob,Date,setTimeout,AbortController,detect,OSV_ORIGIN:'https://api.osv.dev/*',huntCves:options.hunt|| (async()=>({queries:[],skipped:[]})),collectPage(){},collectGlobals(){},chrome:{tabs:{query:async()=>[target],get:async()=>target},scripting:{executeScript:async args=>{calls.push(args);if(args.func.name!=='collectPage'&&args.func.name!=='collectGlobals')return [{documentId:options.checkId||'doc-1',result:url}];return [{documentId:args.world?(options.globalId||'doc-1'):'doc-1',result:args.world?{next:'16.2.10',jquery:'4.0.0'}:{navigationStartedAt:1000,scripts:['https://fixture.test/_next/a.js']}}];}},storage:{session:{get:async()=>options.headers?{'headers:1':options.headers}:{}},local:{get:async()=>options.prefs||{},set:async()=>{}}},permissions:{contains:async()=>!!options.permitted,request:async()=>options.granted!==false}}});
 const source=fs.readFileSync(new URL('../popup.js',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 vm.runInContext(source,context);await new Promise(resolve=>setImmediate(resolve));return {els,calls,context};
}
test('popup renders grouped scan with versions, searches, and explains header permission',async()=>{
 const {els,calls}=await setup();assert.equal(calls.length,3);assert.equal(calls[1].world,'MAIN');assert.equal(els.export.disabled,false);assert.match(els.status.textContent,/2 công nghệ/);
 const flattened=JSON.stringify(els.results.children);assert.match(flattened,/16.2.10/);assert.match(flattened,/4.0.0/);
 els.search.value='absent';els.search.events.input();assert.match(els.results.children[0].textContent,/Không có/);
 await els.headers.events.click();assert.equal(els.headers.disabled,true);assert.match(els.notice.textContent,/Tải lại/);
});
test('restricted page produces useful error with export disabled',async()=>{
 const {els,calls}=await setup('chrome://extensions/');assert.equal(calls.length,0);assert.match(els.status.textContent,/HTTP\/HTTPS/);assert.equal(els.export.disabled,true);assert.equal(els.scan.disabled,false);
});
test('manual CVE Hunt renders version-only status, fresh bypasses cache, exported report includes hunt',async()=>{
 const flags=[];const {els,context}=await setup(undefined,{hunt:async(techs,options)=>{flags.push(options.force);return {queries:[{technology:'jQuery',package:'jquery',version:'4.0.0',status:'complete',versionEvidence:['JavaScript global: jquery version'],advisories:[{id:'TEST',cves:[],severity:'UNKNOWN',summary:'<script>untrusted</script>',status:'version_affected',fixedVersions:[],ranges:[],cvss:[],details:'Fixture',source:'https://osv.dev/vulnerability/TEST',references:[]}]}],skipped:[]};}});
 await els.hunt.events.click();assert.match(els['hunt-status'].textContent,/1 khớp phiên bản/);assert.match(els['hunt-status'].textContent,/Chưa xác minh sink/);assert.match(JSON.stringify(els['hunt-results'].children),/<script>untrusted<\/script>/);
 assert.equal(vm.runInContext('report.cveHunt.queries.length',context),1);await els.fresh.events.click();assert.deepEqual(flags,[false,true]);
});
test('permission denial does not query OSV and auto preference hunts on scan',async()=>{
 let calls=0;const hunt=async()=>{calls++;return {queries:[],skipped:[]};};
 const denied=await setup(undefined,{hunt,granted:false});await denied.els.hunt.events.click();assert.equal(calls,0);assert.match(denied.els['hunt-status'].textContent,/Chưa cấp quyền/);
 await setup(undefined,{hunt,prefs:{autoHunt:true},permitted:true});assert.equal(calls,1);
});
test('new scan aborts previous hunt and discards stale CVE result',async()=>{
 let resolve;const {els}=await setup(undefined,{hunt:()=>new Promise(r=>{resolve=r;})});
 const pending=els.hunt.events.click();await new Promise(r=>setImmediate(r));await els.scan.events.click();resolve({queries:[],skipped:[]});await pending;
 assert.equal(els['hunt-status'].textContent,'Chưa tra CVE.');assert.equal(els.hunt.disabled,false);
});

test('reload at the same URL rejects mixed document snapshots',async()=>{
 for(const options of [{globalId:'doc-2'},{checkId:'doc-2'}]){
  const {els}=await setup(undefined,options);assert.equal(els.export.disabled,true);assert.equal(els.hunt.disabled,true);assert.match(els.status.textContent,/Quét lại/);
 }
});
test('headers from an earlier load at the same URL are not reused',async()=>{
 for(const [observedAt,expected] of [[999,false],[1001,true]]){
  const {context}=await setup(undefined,{headers:{url:'https://fixture.test/',observedAt,headers:[{name:'server',value:'nginx/1.26.3'}]}});
  assert.equal(vm.runInContext('report.headersAvailable',context),expected);
  assert.equal(vm.runInContext("report.technologies.some(t=>t.name==='Nginx')",context),expected);
 }
});
