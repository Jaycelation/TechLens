import test from 'node:test';
import assert from 'node:assert/strict';
import {collectPage,collectGlobals} from '../collector.js';
test('collector tolerates inaccessible CSS, bounds data and reads actual markers',()=>{
 const el={attributes:[{name:'data-radix-trigger',value:''}],classList:{contains:n=>n==='lucide'},hasAttribute:n=>n==='fetchpriority',getAttribute:()=> 'high'};
 const old={document:globalThis.document,performance:globalThis.performance,window:globalThis.window};
 try{
  globalThis.document={querySelectorAll:sel=>sel==='*'?[el]:sel==='meta'?[{name:'generator',content:'Next.js 16.2.10'}]:sel==='script[src]'?[{getAttribute:()=>'/test.js'}]:[],scripts:[{src:'',textContent:'x'.repeat(30000)}],styleSheets:[{get cssRules(){throw Error('CORS')}},{cssRules:[{cssText:'--tw-ring-color: red'}]}]};
  globalThis.performance={getEntriesByType:()=>[{name:'https://x.test/a.js'}]};
  const s=collectPage();assert.ok(s.markers.includes('radix'));assert.ok(s.markers.includes('lucide'));assert.ok(s.markers.includes('priority-hints'));assert.equal(s.inline[0].length,20000);assert.match(s.css,/--tw-ring/);
  globalThis.window={jQuery:{fn:{jquery:'4.0.0'}},next:{version:'16.2.10'},React:{version:'19.2.0'},secret:'NOT_COLLECTED'};
  const g=collectGlobals();assert.equal(g.jquery,'4.0.0');assert.equal(g.next,'16.2.10');assert.ok(!JSON.stringify(g).includes('NOT_COLLECTED'));
  Object.defineProperty(globalThis.window,'Vue',{get(){throw Error('broken getter')}});assert.doesNotThrow(collectGlobals);
 }finally{for(const [key,value] of Object.entries(old))globalThis[key]=value;}
});
