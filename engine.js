// Original fingerprints. These are indicators, not vulnerability assessments.
export const RULES = [
 ['Next.js',['JavaScript frameworks','Web frameworks'], 'urls', '/_next/', 'high'],
 ['React',['JavaScript libraries'], 'markers','^react$', 'medium'],
 ['Vue.js',['JavaScript frameworks'],'urls','(?:^|/)vue(?:[.@/-]|\\.global)', 'high'],
 ['Angular',['JavaScript frameworks'],'markers','^angular:', 'high'],
 ['Svelte',['JavaScript frameworks'],'css','\\.svelte-[a-z0-9]+','medium'],
 ['Nuxt',['Web frameworks'],'urls','/_nuxt/', 'high'],
 ['Astro',['Static site generators'],'urls','/_astro/','high'],
 ['Gatsby',['Static site generators'],'inline','___gatsby|___loader','high'],
 ['jQuery',['JavaScript libraries'],'urls','/jquery(?:[-.]([0-9]+\\.[0-9]+\\.[0-9]+))?(?:\\.min)?\\.js(?:[?#]|$)','high',1],
 ['jQuery CDN',['CDN'],'urls','https?://code\\.jquery\\.com/','high'],
 ['Google Analytics',['Analytics'],'urls','https?://(?:www\\.)?google-analytics\\.com/|https?://www\\.googletagmanager\\.com/gtag/js\\?','high'],
 ['GA4',['Analytics'],'urls','googletagmanager\\.com/gtag/js\\?[^#]*\\bid=G-[A-Z0-9]+|google-analytics\\.com/g/collect','high'],
 ['Google Tag Manager',['Tag managers'],'urls','googletagmanager\\.com/gtm\\.js','high'],
 ['Vercel Analytics',['Analytics'],'urls','/_vercel/insights/|va\\.vercel-scripts\\.com/','high'],
 ['Vercel Speed Insights',['Performance'],'urls','/_vercel/speed-insights/','high'],
 ['Siteimprove',['Analytics'],'urls','(?:siteimproveanalytics\\.com|siteimprove\\.com)/.*(?:js|collect)|siteimproveanalytics\\.io/','high'],
 ['Adobe Fonts',['Font scripts'],'urls','(?:use|p)\\.typekit\\.net/','high'],
 ['Google Fonts',['Font scripts'],'urls','fonts\\.(?:googleapis|gstatic)\\.com/','high'],
 ['Lucide',['Icon libraries'],'markers','^lucide$','high'],
 ['Tailwind CSS',['UI frameworks'],'css','--tw-(?:ring|translate|shadow|border|gradient|space)-','medium'],
 ['Radix UI',['UI frameworks'],'markers','^radix$','high'],
 ['OneTrust',['Cookie compliance'],'urls','(?:cdn\\.cookielaw\\.org|onetrust\\.com)/','high'],
 ['Cookiebot',['Cookie compliance'],'urls','(?:consent|consentcdn)\\.cookiebot\\.com/','high'],
 ['Turbopack',['Development'],'urls','turbopack','medium'],
 ['Priority Hints',['Performance'],'markers','^priority-hints$','high'],
 ['Open Graph',['Miscellaneous'],'meta','^og:','high'],
 ['WordPress',['CMS'],'urls','/wp-(?:content|includes)/','high'],
 ['Shopify',['E-commerce'],'urls','cdn\\.shopify\\.com/','high'],
 ['Drupal',['CMS'],'meta','^generator:Drupal(?: ([0-9.]+))?','high',1],
 ['Bootstrap',['UI frameworks'],'urls','bootstrap(?:@|/|-)([0-9]+\\.[0-9]+\\.[0-9]+)|bootstrap(?:\\.min)?\\.(?:css|js)','high',1],
 ['Cloudflare',['CDN'],'urls','cdnjs\\.cloudflare\\.com/','high'],
 ['jsDelivr',['CDN'],'urls','cdn\\.jsdelivr\\.net/','high'],
 ['unpkg',['CDN'],'urls','unpkg\\.com/','high'],
 ['Hotjar',['Analytics'],'urls','(?:static|script)\\.hotjar\\.com/','high'],
 ['Microsoft Clarity',['Analytics'],'urls','clarity\\.ms/tag/','high'],
 ['Plausible',['Analytics'],'urls','plausible\\.io/js/','high'],
 ['Matomo',['Analytics'],'urls','matomo\\.js(?:[?#]|$)','high'],
 ['Segment',['Analytics'],'urls','cdn\\.segment\\.com/analytics','high'],
 ['Sentry',['Monitoring'],'urls','(?:browser\\.sentry-cdn\\.com|js\\.sentry-cdn\\.com)/','high'],
 ['Alpine.js',['JavaScript frameworks'],'urls','alpinejs(?:@|/)','high'],
 ['HTMX',['JavaScript libraries'],'urls','htmx\\.org(?:@|/)|/htmx(?:\\.min)?\\.js','high'],
 ['D3.js',['JavaScript libraries'],'urls','/d3(?:[.@/-]|\\.min\\.js)','medium'],
 ['Chart.js',['JavaScript libraries'],'urls','chart\\.js(?:@|/)|/chart(?:\\.umd)?(?:\\.min)?\\.js','high'],
 ['Font Awesome',['Icon libraries'],'urls','(?:fontawesome|font-awesome)','high'],
 ['Webflow',['Website builders'],'urls','(?:assets\\.website-files\\.com|cdn\\.prod\\.website-files\\.com)/','high'],
 ['Wix',['Website builders'],'urls','static\\.wixstatic\\.com/','high']
];
export function detect(snapshot={},globals={},headers=[]) {
 const map=new Map();
 const add=(name,categories,confidence,evidence,version)=>{
  if(!map.has(name))map.set(name,{name,categories:[...categories],confidence,versions:[],evidence:[]});
  const t=map.get(name);t.categories=[...new Set([...t.categories,...categories])];if(confidence==='high')t.confidence='high';
  if(version && /^\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?$/.test(version) && !t.versions.includes(version))t.versions.push(version);
  if(!t.evidence.includes(evidence)&&t.evidence.length<8)t.evidence.push(evidence);
 };
 const redact=s=>{try{const u=new URL(s);return u.origin+u.pathname;}catch{return String(s).slice(0,180);}};
 const sources={urls:[...(snapshot.scripts||[]),...(snapshot.links||[]),...(snapshot.resources||[])],markers:snapshot.markers||[],meta:(snapshot.meta||[]).map(m=>m.name+':'+m.content),inline:snapshot.inline||[],css:[snapshot.css||'']};
 for(const [name,categories,source,pattern,confidence,group] of RULES){
  const re=new RegExp(pattern,'i');
  for(const s of sources[source]){const match=re.exec(s);if(match)add(name,categories,confidence,source==='urls'?'Resource: '+redact(s):source==='inline'?'Inline marker: '+match[0].slice(0,100):source+': '+match[0].slice(0,100),group?match[group]:undefined);}
 }
 const defs={jquery:['jQuery',['JavaScript libraries']],next:['Next.js',['JavaScript frameworks','Web frameworks']],react:['React',['JavaScript libraries']],vue:['Vue.js',['JavaScript frameworks']],angular:['AngularJS',['JavaScript frameworks']]};
 for(const [key,[name,cats]] of Object.entries(defs)) if(typeof globals[key]==='string')add(name,cats,'high','JavaScript global: '+key+' version',globals[key]);
 if(globals.nextPresent)add('Next.js',['JavaScript frameworks','Web frameworks'],'high','JavaScript global: next / __NEXT_DATA__');
 if(globals.reactPresent)add('React',['JavaScript libraries'],'high','React renderer registered in devtools hook');
 if(globals.gtm)add('Google Tag Manager',['Tag managers'],'medium','JavaScript global: google_tag_manager');
 if(globals.onetrust)add('OneTrust',['Cookie compliance'],'high','JavaScript global: OneTrust');
 for(const m of snapshot.markers||[])if(m.startsWith('angular:'))add('Angular',['JavaScript frameworks'],'high','DOM: ng-version',m.slice(8));
 for(const m of snapshot.meta||[])if(m.name.toLowerCase()==='generator'){
  const v=/Next\.js(?:\s+v?([\d.]+))?/i.exec(m.content);if(v)add('Next.js',['JavaScript frameworks','Web frameworks'],'high','Meta generator: '+m.content.slice(0,100),v[1]);
 }
 for(const h of headers){const n=h.name.toLowerCase(),v=h.value||'';
  if(n==='x-vercel-id'||n==='x-vercel-cache')add('Vercel',['PaaS'],'high','Response header: '+n);
  if(n==='x-powered-by'&&/next\.js/i.test(v))add('Next.js',['JavaScript frameworks','Web frameworks','Web servers'],'high','Response header: x-powered-by = '+v);
  if(n==='server'&&/nginx/i.test(v))add('Nginx',['Web servers'],'high','Response header: server = '+v,/nginx\/([\d.]+)/i.exec(v)?.[1]);
  if(n==='server'&&/apache/i.test(v))add('Apache',['Web servers'],'high','Response header: server = '+v,/apache\/([\d.]+)/i.exec(v)?.[1]);
  if(n==='cf-ray'||(n==='server'&&/cloudflare/i.test(v)))add('Cloudflare',['CDN'],'high','Response header: '+n);
 }
 return [...map.values()].sort((a,b)=>a.name.localeCompare(b.name));
}
