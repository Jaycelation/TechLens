// Optional integration smoke test. Sends only jquery + public versions to OSV.
// Run manually: node tests/live-osv.mjs (requires internet, not part of npm test).
import assert from 'node:assert/strict';
import {huntCves} from '../cve.js';
for(const version of ['3.4.1','3.5.0','4.0.0']){
 const result=await huntCves([{name:'jQuery',versions:[version],evidence:['Integration fixture; not a target website']}]);
 const q=result.queries[0];assert.equal(q.status,'complete',JSON.stringify(q));
 const known=q.advisories.filter(a=>a.cves.includes('CVE-2020-11022')||a.cves.includes('CVE-2020-11023'));
 if(version==='3.4.1'){assert.equal(known.length,2);assert.ok(known.every(a=>a.status==='version_affected'&&a.sinkStatus==='unverified'));}
 else assert.equal(known.length,0);
 console.log(`${version}: ${q.advisories.length} advisory, regression for CVE-2020-11022/11023 passed`);
}
