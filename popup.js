import {collectPage,collectGlobals} from './collector.js';
import {detect} from './engine.js';
import {huntCves,OSV_ORIGIN} from './cve.js';
const $=id=>document.getElementById(id);let report=null,tab=null,origin=null,huntController=null;
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function render(){
 $('results').replaceChildren();if(!report)return;
 const q=$('search').value.toLowerCase().trim();const groups=new Map();
 const visible=report.technologies.filter(t=>(t.name+' '+t.categories.join(' ')).toLowerCase().includes(q));
 $('count').textContent=`${visible.length} / ${report.technologies.length} công nghệ`;
 for(const t of visible)for(const category of t.categories){if(!groups.has(category))groups.set(category,[]);groups.get(category).push(t);}
 for(const [cat,techs] of [...groups].sort(([a],[b])=>a.localeCompare(b))){
  $('results').append(node('h2',cat));
  for(const t of techs){const card=node('article',undefined,'card'),row=node('div',undefined,'row');
   row.append(node('span',t.name,'name'));if(t.versions.length)row.append(node('span',t.versions.join(' / '),'version'));
   row.append(node('span',t.confidence==='high'?'Tin cậy cao':'Dấu hiệu',`confidence ${t.confidence}`));card.append(row);
   const details=node('details'),list=node('ul');details.append(node('summary','Xem bằng chứng'));for(const ev of t.evidence)list.append(node('li',ev));details.append(list);card.append(details);$('results').append(card);
  }
 }
 if(!visible.length)$('results').append(node('p',q?'Không có kết quả phù hợp.':'Chưa tìm thấy dấu vết được hỗ trợ.','empty'));
}
async function scan(){
 huntController?.abort();huntController=null;$('hunt').disabled=true;$('fresh').disabled=true;$('hunt-results').replaceChildren();$('hunt-status').textContent='Chưa tra CVE.';
 $('scan').disabled=true;$('export').disabled=true;$('headers').disabled=true;origin=null;tab=null;report=null;$('results').replaceChildren();$('status').textContent='Đang đọc dấu vết công nghệ…';
 try{
  [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  if(!tab?.id||!/^https?:\/\//.test(tab.url||''))throw new Error('Hãy mở một trang HTTP/HTTPS. Trang hệ thống và Chrome Web Store không cho phép quét.');
  origin=new URL(tab.url).origin;const target={tabId:tab.id};$('host').textContent=new URL(tab.url).host;
  const [page,global]=await Promise.all([chrome.scripting.executeScript({target,func:collectPage}),chrome.scripting.executeScript({target,world:'MAIN',func:collectGlobals})]);
  // Avoid mixing results if navigation happened during execution.
  const current=await chrome.tabs.get(tab.id);if(current.url!==tab.url)throw new Error('Trang đã chuyển hướng. Bấm Quét lại.');
  const key='headers:'+tab.id;const cache=(await chrome.storage.session.get(key))[key];
  const sameDocument=cache&&cache.url.split('#')[0]===tab.url.split('#')[0];
  const headers=sameDocument?cache.headers:[];
  report={site:origin,scannedAt:new Date().toISOString(),headersAvailable:!!sameDocument,technologies:detect(page[0]?.result,global[0]?.result,headers)};
  $('status').textContent=`${report.technologies.length} công nghệ · ${sameDocument?'Có response headers':'DOM, JavaScript và resources'}`;
  $('export').disabled=false;$('hunt').disabled=false;$('fresh').disabled=false;render();
  const permitted=await chrome.permissions.contains({origins:[origin+'/*']});$('headers').disabled=permitted;$('headers').textContent=permitted?'Headers đã bật — tải lại trang nếu cần':'Bật đọc headers cho site này';
  const prefs=await chrome.storage.local.get('autoHunt');$('auto-hunt').checked=!!prefs.autoHunt;
  if(prefs.autoHunt && await chrome.permissions.contains({origins:[OSV_ORIGIN]}))void runHunt(false);
 }catch(e){$('status').textContent=e.message||'Không thể quét trang.';}
 finally{$('scan').disabled=false;}
}
$('scan').addEventListener('click',scan);$('search').addEventListener('input',render);
$('headers').addEventListener('click',async()=>{
 if(!origin)return;
 try{const granted=await chrome.permissions.request({origins:[origin+'/*']});if(granted){$('headers').disabled=true;$('headers').textContent='Đã bật cho site này';$('notice').textContent='Tải lại trang rồi bấm Quét lại để lấy headers.';}}catch(e){$('notice').textContent=e.message;}
});
$('export').addEventListener('click',()=>{
 if(!report)return;const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='techlens-'+new URL(report.site).hostname+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
function link(url,text){const a=node('a',text);a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a;}
function renderHunt(data){
 $('hunt-results').replaceChildren();let matches=0,review=0,errors=0,partial=0;
 for(const q of data.queries){
  const section=node('div',undefined,'finding');section.append(node('strong',`${q.technology} ${q.version} · npm/${q.package}`));
  const proof=node('details');proof.append(node('summary','Bằng chứng nhận diện phiên bản'));const evidence=node('ul');for(const ev of q.versionEvidence||[])evidence.append(node('li',ev));proof.append(evidence);section.append(proof);
  if(q.status==='error'){errors++;section.append(node('p',`Chưa kiểm tra: ${q.error}`));}
  else{
   if(q.status==='partial'){partial++;section.append(node('p','Kết quả bị giới hạn; có thể còn advisory chưa tải.'));}
   section.append(node('p',`${q.cached?'Cache ≤ 6 giờ · ':''}${q.advisories.length} advisory liên quan`));
   if(!q.advisories.length)section.append(node('p','Không tìm thấy trong dữ liệu OSV đã kiểm tra. Không phải chứng nhận an toàn.'));
   for(const a of q.advisories){
    if(a.status==='version_affected')matches++;else review++;
    const item=node('details');item.append(node('summary',`${a.cves.join(', ')||a.id} · ${a.severity}`));
    item.append(node('p',a.summary));item.append(node('p',a.status==='version_affected'?'Khớp dải phiên bản · sink chưa xác minh':'Ứng viên từ OSV · cần kiểm tra dải phiên bản','review'));
    item.append(node('p',`Bản vá theo advisory (các nhánh): ${a.fixedVersions.join(', ')||'Chưa công bố trong dữ liệu'}`));
    const ranges=node('pre',JSON.stringify(a.ranges,null,2),'advisory-details');item.append(ranges);
    if(a.cvss.length)item.append(node('p',a.cvss.map(s=>s.vector).join(' / ')));
    item.append(node('p',a.details,'advisory-details'));
    item.append(link(a.source,'Mở advisory trên OSV'));
    const refs=node('ul');for(const u of a.references){const li=node('li');li.append(link(u,u));refs.append(li);}item.append(refs);
    item.append(node('p','Xác minh tiếp: version trên backend → điều kiện trong advisory → input tới sink → impact có thể tái hiện.'));
    section.append(item);
   }
  }
  $('hunt-results').append(section);
 }
 const d=node('details');d.append(node('summary',`${data.skipped.length} công nghệ chưa kiểm tra`));const ul=node('ul');for(const s of data.skipped)ul.append(node('li',`${s.technology}: ${s.reason}`));d.append(ul);$('hunt-results').append(d);
 $('hunt-status').textContent=`${matches} khớp phiên bản · ${review} cần review · ${errors} lỗi${partial?' · '+partial+' kết quả chưa đầy đủ':''}. Chưa xác minh sink/khả năng khai thác.`;
}
async function runHunt(force){
 if(!report)return;
 const owner=report;huntController?.abort();const controller=new AbortController();huntController=controller;
 $('hunt').disabled=true;$('fresh').disabled=true;$('hunt-status').textContent='Đang tra OSV…';
 try{
  const data=await huntCves(owner.technologies,{cache:chrome.storage.session,force,signal:controller.signal,onProgress:t=>{if(report===owner&&!controller.signal.aborted)$('hunt-status').textContent='Đang tra: '+t;}});
  if(report!==owner||controller.signal.aborted)return;owner.cveHunt=data;renderHunt(data);
 }catch(e){if(report===owner&&!controller.signal.aborted)$('hunt-status').textContent='Chưa kiểm tra: '+e.message;}
 finally{if(report===owner&&huntController===controller){$('hunt').disabled=false;$('fresh').disabled=false;huntController=null;}}
}
async function manualHunt(force){
 try{const granted=await chrome.permissions.request({origins:[OSV_ORIGIN]});if(granted)await runHunt(force);else $('hunt-status').textContent='Chưa cấp quyền OSV; chưa tra CVE.';}catch(e){$('hunt-status').textContent=e.message;}
}
$('hunt').addEventListener('click',()=>manualHunt(false));$('fresh').addEventListener('click',()=>manualHunt(true));
$('auto-hunt').addEventListener('change',async()=>{
 const enabled=$('auto-hunt').checked;
 try{if(enabled&&!await chrome.permissions.request({origins:[OSV_ORIGIN]})){$('auto-hunt').checked=false;return;}await chrome.storage.local.set({autoHunt:enabled});if(enabled)await runHunt(false);}catch(e){$('auto-hunt').checked=false;$('hunt-status').textContent=e.message;}
});
scan();
