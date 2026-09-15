export const level = score => score<=25?'low':score<=50?'caution':score<=75?'high':'critical';
export const levels={low:'منخفضة',caution:'تحتاج انتباهًا',high:'مرتفعة',critical:'حرجة'};
export const scanTypes={message:'رسالة',link:'رابط',phone:'رقم هاتف',screenshot:'صورة'};
const normalize=text=>text.normalize('NFKD').replace(/[\u064B-\u065F\u0670]/g,'').toLowerCase().replace(/[إأآٱ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/[^\p{L}\p{N}:/._+]+/gu,' ').replace(/\s+/g,' ').trim();
// Same rule weights, categories, signal identifiers and thresholds as LocalScamAnalyzer on iOS.
const rules=[
 ['urgency',['عاجل','فورا','الان','بسرعه','urgent','immediately','act now','right now'],'استعجال وضغط','يحاول دفعك للتصرف قبل التحقق.',14,'pressure','urgency'],
 ['threat',['تم ايقاف','اغلاق الحساب','سيتم تعليق','account has been suspended','account will be closed','legal action'],'تهديد بإيقاف حساب','تحقق من حالة حسابك عبر التطبيق الرسمي.',22,'pressure','threat'],
 ['otpRequest',['رمز تحقق','رمز التحقق','otp','verification code','one time password'],'ذكر رمز تحقق','وجود رمز تحقق مؤشر يحتاج سياقًا؛ لا تشاركه مع أي شخص.',45,'sensitiveData','otp'],
 ['credentialsRequest',['كلمه المرور','الرقم السري','حدث بياناتك','password','pin number','update your details','login details'],'طلب بيانات حساسة','لا تدخل كلمة المرور أو بياناتك عبر رسالة مفاجئة.',28,'sensitiveData','credentials'],
 ['paymentRequest',['حول المبلغ','تحويل','ادفع','رسوم شحن','send money','transfer','pay now','shipping fee'],'طلب دفع أو تحويل','أوقف التحويل وتحقق من الجهة عبر قناة مستقلة.',27,'financial','payment'],
 ['bankImpersonation',['موظف البنك','من البنك','خدمه العملاء','bank employee','from your bank','bank representative'],'ادعاء تمثيل البنك','اسم الجهة أو صفة الموظف لا يثبتان الهوية.',26,'identity','bank'],
 ['prize',['ربحت','جائزه','مبروك','you won','winner','prize','reward'],'جائزة غير متوقعة','الجوائز المفاجئة قد تكون وسيلة لاستدراج البيانات.',24,'deception','prize'],
 ['secrecy',['لا تخبر','لا تتصل','سرا','keep this secret','do not tell',"don't call"],'طلب السرية','منعك من سؤال الآخرين علامة ضغط.',25,'pressure','secrecy'],
 ['impersonation',['غيرت رقمي','رقم جديد','انا مسؤول','changed my number','new number','government official'],'احتمال انتحال هوية','اتصل بالرقم المحفوظ مسبقًا للتأكد.',22,'identity','impersonation'],
 ['link',['اضغط الرابط','عبر الرابط','click the link','tap this link','http://','https://'],'رابط داخل الرسالة','راجع اسم النطاق قبل فتحه.',12,'link','link'],
 ['crypto',['عملات رقميه','بيتكوين','crypto','bitcoin','wallet'],'عملات رقمية أو محفظة','تحقق من أي طلب استثمار أو تحويل رقمي.',24,'financial','crypto'],
 ['remoteAccess',['تحكم عن بعد','ثبت البرنامج','remote access','install this app','screen sharing'],'طلب وصول للجهاز','لا تثبت برامج تحكم بطلب من جهة غير متحقق منها.',38,'sensitiveData','remote']
];
export const signalText=Object.fromEntries(rules.map(r=>[r[0],{title:r[2],description:r[3]}]));
export const recommendationText={
 'recommendation.noLink':'لا تفتح الرابط قبل التحقق من النطاق والجهة.',
 'recommendation.noCode':'لا تشارك رموز التحقق أو كلمات المرور.',
 'recommendation.openBank':'افتح تطبيق البنك بنفسك للتأكد من الطلب.',
 'recommendation.pausePayment':'أوقف أي دفع أو تحويل حتى تتأكد.',
 'recommendation.officialChannel':'تواصل مع الجهة عبر قناة رسمية مستقلة عن الرسالة.',
 'recommendation.stayCautious':'لا توجد مؤشرات قوية، لكن ابقَ حذرًا من الطلبات المفاجئة.',
 'recommendation.verifyUnexpected':'تحقق من أي تواصل أو طلب غير متوقع.',
 'recommendation.verifyDomain':'قارن اسم النطاق بالموقع الرسمي حرفًا بحرف.'
};
function signal(id,title,description,weight,category='link',key=id){signalText[id]={title,description};return {id,titleKey:`signal.${key}.title`,descriptionKey:`signal.${key}.description`,severity:weight>=38?'critical':weight>=22?'high':'caution',weight,category};}
export function analyze(content,type='message') {
 if(typeof content!=='string'||!content.trim()||content.length>12000)throw new Error('اكتب محتوى للفحص لا يتجاوز ١٢ ألف حرف.');
 let signals=[],recommendations=[],details=[];
 if(type==='link') {
  const raw=content.trim(),prepared=raw.includes('://')?raw:'https://'+raw;
  let url;try{url=new URL(prepared);if(!url.hostname)throw Error();}catch{return finish(type,35,[signal('invalidURL','صيغة رابط غير صالحة','تعذر استخراج اسم نطاق واضح.',35,'link','invalidURL')],['recommendation.noLink','recommendation.officialChannel'],[]);}
  const host=url.hostname.toLowerCase(),words=['login','verify','secure','account','update','wallet','bank','prize','free','urgent'];
  const add=(...args)=>signals.push(signal(...args));
  if(url.protocol!=='https:')add('noHTTPS','اتصال غير مشفر','الرابط لا يستخدم HTTPS.',18,'link','https');
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host))add('ipHost','عنوان IP بدل النطاق','قد يخفي الجهة التي تستضيف الصفحة.',28,'link','ip');
  if(host.includes('xn--'))add('punycode','نطاق مرمز','قد يحتوي حروفًا متشابهة بصريًا؛ راجعه بعناية.',24);
  if(['bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','shorturl.at'].includes(host))add('shortener','رابط مختصر','الوجهة الحقيقية غير واضحة من الرابط.',22);
  if(host.split('.').length>4)add('subdomains','نطاقات فرعية كثيرة','تأكد أن اسم الجهة ليس مجرد نطاق فرعي.',14);
  if(words.some(w=>prepared.toLowerCase().includes(w)))add('suspiciousKeyword','كلمات تستهدف الثقة','قد تكون كلمات شرعية؛ لا تكفي وحدها لإثبات الاحتيال.',14,'link','urlKeyword');
  if(host.includes('-')&&words.some(w=>host.includes(w)))add('typosquatting','صيغة قد تقلد جهة','تحقق من التهجئة مقابل الموقع الرسمي.',15,'link','typosquat');
  const originalHost=raw.replace(/^[a-z]+:\/\//i,'').split('/')[0];
  if(/[a-zA-Z]/.test(originalHost)&&/[\u0400-\u052F\u0600-\u06FF]/.test(originalHost))add('mixedScript','حروف من أنظمة مختلفة','قد تُستخدم حروف مشابهة لتقليد اسم نطاق.',26);
  if(url.port&&!['80','443'].includes(url.port))add('port','منفذ غير معتاد','الرابط يتصل عبر منفذ غير شائع.',18);
  if(raw.includes('%'))add('encoded','أجزاء مرمزة','راجع الأجزاء المرمزة في الرابط.',12);
  if(url.username)add('userinfo','بيانات دخول داخل الرابط','قد يوهمك الجزء قبل @ باسم موقع مختلف.',25);
  details=[{key:'النطاق',value:host},{key:'التشفير',value:url.protocol==='https:'?'HTTPS':'غير HTTPS'},{key:'النطاقات الفرعية',value:String(Math.max(0,host.split('.').length-2))}];
  const score=signals.reduce((s,x)=>s+x.weight,0);recommendations=level(score)==='low'?['recommendation.stayCautious','recommendation.verifyDomain']:['recommendation.noLink','recommendation.officialChannel','recommendation.verifyDomain'];
 }else if(type==='phone'){
  const compact=content.replace(/[٠-٩]/g,c=>String(c.charCodeAt(0)-1632)).replace(/[^0-9+]/g,'');
  if(!/^\+?[0-9]{7,15}$/.test(compact)||(compact.startsWith('+966')&&!/^\+9665[0-9]{8}$/.test(compact)))signals.push(signal('phoneFormat','صيغة رقم غير معتادة','تحليل الصيغة فقط؛ ليس لدينا قاعدة بلاغات عن أصحاب الأرقام.',28,'identity','phoneFormat'));
  if(/([0-9])\1{5,}/.test(compact))signals.push(signal('phonePattern','نمط متكرر','النمط غير معتاد لكنه لا يثبت الاحتيال.',18,'identity','phonePattern'));
  if(compact==='+966500000999')signals.push(signal('demoReport','رقم تجريبي','هذا رقم عرض تجريبي وليس بلاغًا حقيقيًا.',55,'identity','demoReport'));
  recommendations=['recommendation.officialChannel','recommendation.verifyUnexpected'];details=[{key:'الفحص',value:'صيغة الرقم فقط، دون كشف هوية أو سجل بلاغات'}];
 }else{
  const text=normalize(content);
  signals=rules.filter(r=>r[1].some(p=>text.includes(normalize(p)))).map(r=>signal(r[0],r[2],r[3],r[4],r[5],r[6]));
  const has=id=>signals.some(s=>s.id===id);
  if(has('link'))recommendations.push('recommendation.noLink');if(has('otpRequest')||has('credentialsRequest'))recommendations.push('recommendation.noCode');if(has('bankImpersonation'))recommendations.push('recommendation.openBank');if(has('paymentRequest'))recommendations.push('recommendation.pausePayment');
  if(signals.length)recommendations.push('recommendation.officialChannel');if(!recommendations.length)recommendations=['recommendation.stayCautious','recommendation.verifyUnexpected'];
 }
 const synergy=['message','screenshot'].includes(type)?(signals.length>=3?8:signals.length===2?3:0):0;
 return finish(type,signals.reduce((s,x)=>s+x.weight,0)+synergy,signals,recommendations.slice(0,4),details);
}
function finish(type,score,signals,recommendations,details){score=Math.min(100,score);return {id:crypto.randomUUID(),date:new Date().toISOString(),scanTypeRaw:type,riskScore:score,riskLevelRaw:level(score),signals,recommendations,details,sourceRaw:'manual'};}
export function assessPassword(p) {
 const checks=[['١٢ حرفًا على الأقل',[...p].length>=12],['حروف كبيرة',/[A-Z]/.test(p)],['حروف صغيرة',/[a-z]/.test(p)],['أرقام',/[0-9]/.test(p)],['رموز',/[^A-Za-z0-9]/.test(p)]];
 return {score:checks.filter(c=>c[1]).length*20,checks};
}
function randomIndex(n){const limit=Math.floor(256/n)*n;let b;do{b=crypto.getRandomValues(new Uint8Array(1))[0];}while(b>=limit);return b%n;}
export function generatePassword(length,groups) {
 if(!groups.length)throw new Error('اختر نوعًا واحدًا من الحروف على الأقل.');
 const all=groups.join(''),chars=groups.map(g=>g[randomIndex(g.length)]);
 while(chars.length<Math.min(64,Math.max(8,length)))chars.push(all[randomIndex(all.length)]);
 for(let i=chars.length-1;i>0;i--){const j=randomIndex(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}return chars.join('');
}
export async function digest(data,algorithm='SHA-256'){const bytes=typeof data==='string'?new TextEncoder().encode(data):data;return [...new Uint8Array(await crypto.subtle.digest(algorithm,bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');}
async function derive(password,salt){const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
// iOS-compatible v1: version(1) + salt(16) + nonce(12) + ciphertext + authentication tag(16).
export async function encrypt(text,password){if(!text||!password)throw Error('أدخل النص وكلمة المرور.');const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),key=await derive(password,salt),cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(text)));const bytes=new Uint8Array(29+cipher.length);bytes[0]=1;bytes.set(salt,1);bytes.set(iv,17);bytes.set(cipher,29);return btoa([...bytes].map(b=>String.fromCharCode(b)).join(''));}
export async function decrypt(encoded,password){try{const bytes=Uint8Array.from(atob(encoded.trim()),c=>c.charCodeAt(0));if(bytes[0]!==1||bytes.length<45||!password)throw Error();const key=await derive(password,bytes.slice(1,17));return new TextDecoder('utf-8',{fatal:true}).decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(17,29)},key,bytes.slice(29)));}catch{throw Error('تعذر فك التشفير؛ تأكد من كلمة المرور وسلامة النص.');}}
export async function readImage(file){if(!['image/jpeg','image/png','image/webp'].includes(file.type)||file.size>10*1024*1024)throw Error('اختر صورة JPG أو PNG أو WebP لا تتجاوز ١٠ ميغابايت.');const bitmap=await createImageBitmap(file);const scale=Math.min(1,1600/Math.max(bitmap.width,bitmap.height)),canvas=document.createElement('canvas');canvas.width=bitmap.width*scale;canvas.height=bitmap.height*scale;canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);bitmap.close();const dataURL=canvas.toDataURL('image/jpeg',.72);return {mimeType:'image/jpeg',data:dataURL.split(',')[1],dataURL};}
