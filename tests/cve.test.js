import test from 'node:test';
import assert from 'node:assert/strict';
import {compareVersions,matchAffected,normalizeAdvisory,planHunt,huntCves} from '../cve.js';
const q={technology:'jQuery',package:'jquery',version:'3.4.1'};
const record=(events=[{introduced:'1.12.0'},{fixed:'3.5.0'}])=>({id:'GHSA-test-fixture-only',aliases:['CVE-2099-99999'],summary:'Synthetic test advisory',affected:[{package:{ecosystem:'npm',name:'jquery'},ranges:[{type:'SEMVER',events}]}],references:[{url:'javascript:alert(1)'},{url:'https://example.org/advisory'}]});
const technologies=[{name:'jQuery',versions:['3.4.1'],evidence:['JavaScript global: jquery version']}];
const response=data=>({ok:true,json:async()=>data});
const cache=()=>{const state={};return {state,get:async k=>({[k]:state[k]}),set:async data=>Object.assign(state,data)};};
test('strict SemVer includes prerelease precedence, ignores build, rejects partial',()=>{
 assert.equal(compareVersions('1.2.3','1.2.3+build'),0);
 assert.equal(compareVersions('1.10.0','1.9.99'),1);
 const ordered=['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta','1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0'];
 for(let i=1;i<ordered.length;i++)assert.equal(compareVersions(ordered[i-1],ordered[i]),-1);
 for(const v of ['1.2','01.2.3','v1.2.3','1.2.3-alpha.01'])assert.equal(compareVersions(v,'1.2.3'),null);
});
test('matching includes introduced, excludes fixed; latest release not automatically affected',()=>{
 const r=record();assert.equal(matchAffected(r,'jquery','1.12.0'),'affected');assert.equal(matchAffected(r,'jquery','3.4.1'),'affected');assert.equal(matchAffected(r,'jquery','3.5.0'),'unaffected');assert.equal(matchAffected(r,'jquery','4.0.0'),'unaffected');assert.equal(matchAffected(r,'jquery','1.11.9'),'unaffected');
});
test('multiple vulnerable intervals and inclusive last_affected/limit',()=>{
 const r=record([{introduced:'0'},{fixed:'1.0.0'},{introduced:'2.0.0'},{last_affected:'2.2.0'},{introduced:'3.0.0'},{limit:'3.1.0'}]);
 for(const v of ['0.9.0','2.0.0','2.2.0','3.0.5'])assert.equal(matchAffected(r,'jquery',v),'affected',v);
 for(const v of ['1.0.0','1.5.0','2.2.1','3.1.0'])assert.equal(matchAffected(r,'jquery',v),'unaffected',v);
});
test('ecosystem/package identity, unsupported ranges, and exact version list',()=>{
 const r=record();r.affected[0].package.ecosystem='NuGet';assert.equal(matchAffected(r,'jquery','3.4.1'),'unknown');
 r.affected[0].package.ecosystem='npm';r.affected[0].ranges[0].type='GIT';assert.equal(matchAffected(r,'jquery','3.4.1'),'unknown');
 r.affected[0].versions=['3.4.1'];assert.equal(matchAffected(r,'jquery','3.4.1'),'affected');
});
test('no version guesses, no conflicting versions, and no inferred react-server-dom package',()=>{
 const p=planHunt([{name:'Next.js',versions:[]},{name:'jQuery',versions:['3.4.1','4.0.0']},{name:'Vue.js',versions:['3.4']},{name:'Nginx',versions:['1.24.0']},{name:'React',versions:['19.2.0']}]);
 assert.equal(p.skipped.length,4);assert.deepEqual(p.queries.map(q=>q.package),['react']);
});
test('advisory excludes withdrawn and patched versions, keeps unknown review, safe references',()=>{
 assert.equal(normalizeAdvisory({...record(),withdrawn:'2020-01-01'},q),null);
 assert.equal(normalizeAdvisory(record(),{...q,version:'3.5.0'}),null);
 const a=normalizeAdvisory(record(),q);assert.equal(a.status,'version_affected');assert.equal(a.sinkStatus,'unverified');assert.deepEqual(a.fixedVersions,['3.5.0']);assert.deepEqual(a.references,['https://example.org/advisory']);
 const r=record();r.affected=[];assert.equal(normalizeAdvisory(r,q).status,'needs_review');
});
test('pagination uses tokens and transmits only package/version; deduplicates',async()=>{
 const bodies=[];const out=await huntCves(technologies,{fetchFn:async(url,options)=>{assert.equal(url,'https://api.osv.dev/v1/query');assert.equal(options.credentials,'omit');assert.equal(options.referrerPolicy,'no-referrer');const body=JSON.parse(options.body);bodies.push(body);return response(bodies.length===1?{vulns:[record()],next_page_token:'page2'}:{vulns:[record()]});}});
 assert.equal(bodies.length,2);assert.equal(bodies[1].page_token,'page2');assert.deepEqual(Object.keys(bodies[0]).sort(),['package','version']);assert.equal(out.queries[0].advisories.length,1);assert.equal(out.sinkVerified,false);
});
test('cache reuses result; force bypasses it',async()=>{
 const c=cache();let requests=0;const options={cache:c,fetchFn:async()=>{requests++;return response({vulns:[record()]});}};
 await huntCves(technologies,options);const out=await huntCves(technologies,options);assert.equal(out.queries[0].cached,true);assert.equal(requests,1);
 await huntCves(technologies,{...options,force:true});assert.equal(requests,2);
});
test('HTTP failure cannot become clean report; pagination cap is partial',async()=>{
 const error=await huntCves(technologies,{fetchFn:async()=>({ok:false,status:429})});assert.equal(error.queries[0].status,'error');assert.match(error.queries[0].error,/429/);
 const partial=await huntCves(technologies,{fetchFn:async()=>response({next_page_token:'more'})});assert.equal(partial.queries[0].status,'partial');
});
test('expired cache refetched, abort captured, and cache quota does not drop results',async()=>{
 const c=cache();c.state['cve:npm:jquery@3.4.1']={at:0,payload:{vulns:[]}};let calls=0;
 const out=await huntCves(technologies,{cache:c,fetchFn:async()=>{calls++;return response({vulns:[record()]});}});assert.equal(calls,1);assert.equal(out.queries[0].advisories.length,1);
 const controller=new AbortController();controller.abort();const aborted=await huntCves(technologies,{signal:controller.signal,fetchFn:async()=>{throw Error('should not fetch')}});assert.equal(aborted.queries[0].status,'error');
 const quota=await huntCves(technologies,{cache:{get:async()=>({}),set:async()=>{throw Error('quota')}},fetchFn:async()=>response({vulns:[record()]})});assert.equal(quota.queries[0].advisories.length,1);
});
test('empty ranges remain unknown and different package advisories are excluded',()=>{
 const r=record();r.affected[0].ranges[0].events=[];assert.equal(matchAffected(r,'jquery','3.4.1'),'unknown');
 r.affected[0].package.name='unrelated';assert.equal(normalizeAdvisory(r,q),null);
});
test('SemVer rejects empty build identifiers',()=>{
 for(const version of ['1.2.3+..','1.2.3+build.','1.2.3+.build','1.2.3+a..b'])assert.equal(compareVersions(version,'1.2.3'),null);
 assert.equal(compareVersions('1.2.3+build.001','1.2.3'),0);
});
test('broken and malformed cache fall back to network; abort also applies to cache hits',async()=>{
 for(const c of [{get:async()=>{throw Error('storage unavailable')}},{get:async key=>({[key]:{at:Date.now(),payload:{vulns:'bad'}}})}]){
  const out=await huntCves(technologies,{cache:c,fetchFn:async()=>response({vulns:[record()]})});assert.equal(out.queries[0].status,'complete');assert.equal(out.queries[0].advisories.length,1);
 }
 const c=cache();await huntCves(technologies,{cache:c,fetchFn:async()=>response({vulns:[]})});const controller=new AbortController();controller.abort();
 const out=await huntCves(technologies,{cache:c,signal:controller.signal});assert.equal(out.queries[0].status,'error');
});
test('invalid provider objects are errors, never clean results',async()=>{
 for(const data of [null,[],{next_page_token:42},{vulns:{}}]){const out=await huntCves(technologies,{fetchFn:async()=>response(data)});assert.equal(out.queries[0].status,'error');}
});
test('parallel lookup is bounded and output retains input order',async()=>{
 const techs=['jQuery','React','Next.js','Vue.js','Bootstrap'].map(name=>({name,versions:['1.0.0']}));let active=0,max=0;
 const out=await huntCves(techs,{fetchFn:async()=>{active++;max=Math.max(max,active);await new Promise(r=>setTimeout(r,10));active--;return response({vulns:[]});}});
 assert.equal(max,3);assert.deepEqual(out.queries.map(q=>q.technology),techs.map(t=>t.name));
});
test('later pagination failure preserves matches as partial and does not cache incomplete data',async()=>{
 let calls=0;const c=cache();const out=await huntCves(technologies,{cache:c,fetchFn:async()=>++calls===1?response({vulns:[record()],next_page_token:'next'}):{ok:false,status:503}});
 assert.equal(out.queries[0].status,'partial');assert.equal(out.queries[0].advisories.length,1);assert.match(out.queries[0].warning,/503/);assert.deepEqual(c.state,{});
});
