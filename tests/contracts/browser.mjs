import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,pbkdf2Sync,createHash} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {chromium,expect} from '@playwright/test';
import {base,fixture,localSql} from './fixtures.mjs';

const password=process.env.RATCHET_BROWSER_PASSWORD??'Browser synthetic password 2026!';
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=','base64');
const pdf=Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

async function seedLogin(){
 if(process.env.RATCHET_BROWSER_LOGIN)return{login:process.env.RATCHET_BROWSER_LOGIN};
 const f=await fixture(),login='browser-'+randomUUID(),salt=randomBytes(16),now=new Date().toISOString();
 const verifier=pbkdf2Sync(password,salt,600000,32,'sha256').toString('base64url');
 await localSql(`INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,created_at,updated_at) VALUES('${f.user_id}','${login}','PBKDF2-SHA256',600000,'${salt.toString('base64url')}','${verifier}','${now}','${now}');`);
 return {...f,login};
}
async function login(page,credentials){
 await page.goto(base);await expect(page.getByRole('heading',{name:'Ingresar',exact:true})).toBeVisible({timeout:30000});
 await page.getByLabel('Usuario',{exact:true}).fill(credentials.login);await page.getByLabel('Contraseña',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Ingresar',exact:true}).click();
 await expect(page.locator('.options-menu-button')).toBeVisible({timeout:60000});
}
async function options(page,section){
 await page.locator('.options-menu-button').click();
 await page.getByRole('dialog',{name:'Opciones de Ratchet'}).getByRole('button',{name:section,exact:false}).click();
 return page.getByRole('dialog',{name:'Seguridad y administración de la cuenta'});
}
async function send(page,text){await page.getByPlaceholder('Mensaje',{exact:true}).fill(text);await page.getByRole('button',{name:'Enviar',exact:true}).click();}
async function visibleMessage(page,text){await expect(page.locator('.bubble > p').filter({hasText:new RegExp('^'+text+'$')})).toHaveCount(1,{timeout:60000});}
async function downloadAttachments(sender,receiver,label,files){
 await sender.locator('.attach-button input[type=file]').setInputFiles(files);
 await expect(sender.locator('.prepared-attachments > span')).toHaveCount(files.length,{timeout:60000});
 await send(sender,label);await visibleMessage(receiver,label);
 const bubble=receiver.locator('.bubble').filter({has:receiver.locator('p').filter({hasText:new RegExp('^'+label+'$')})});
 await expect(bubble.locator('.attachment-inline-preview')).toHaveCount(files.length,{timeout:60000});
 for(let index=0;index<files.length;index++){
  await bubble.locator('.attachment-inline-preview').nth(index).click();
  const dialog=receiver.getByRole('dialog',{name:'Vista previa del archivo'});
  await expect(dialog.getByRole('button',{name:'Descargar',exact:true})).toBeVisible({timeout:60000});
  const waiting=receiver.waitForEvent('download');await dialog.getByRole('button',{name:'Descargar',exact:true}).click();
  const downloaded=await waiting;assert.equal(downloaded.suggestedFilename(),files[index].name);
  const path=await downloaded.path();assert.ok(path);assert.equal(digest(await readFile(path)),digest(files[index].buffer));
  await dialog.getByRole('button',{name:'Cerrar vista previa'}).click();
 }
 await expect(sender.locator('.prepared-attachments > span')).toHaveCount(0);
}

test('real desktop and mobile browsers deliver messages with encrypted storage, files, wallpapers, and recover after offline reload',{timeout:900000},async t=>{
 const credentials=await seedLogin();const output=resolve('tests/browser/results');await mkdir(output,{recursive:true});
 const browser=await chromium.launch({channel:'chrome',headless:true});
 const adminContext=await browser.newContext({viewport:{width:1365,height:900},serviceWorkers:'block',acceptDownloads:true});
 const customerContext=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,serviceWorkers:'block',acceptDownloads:true});
 const admin=await adminContext.newPage(),customer=await customerContext.newPage();
 const navigationTrace=[];
 await customer.exposeBinding('__ratchetNavigationTrace',(_source,event)=>{navigationTrace.push(event);if(navigationTrace.length>180)navigationTrace.shift();});
 await customer.addInitScript(()=>{
  const trace=(type,detail={})=>{void window.__ratchetNavigationTrace({type,...detail,url:location.href,state:history.state,length:history.length,time:performance.now()}).catch(()=>{});};
  for(const name of ['pushState','replaceState','back','forward','go']){
   const original=history[name];history[name]=function(...args){trace('history.'+name,{args,stack:new Error().stack});return Reflect.apply(original,this,args);};
  }
  for(const name of ['touchstart','touchmove','touchend','touchcancel'])document.addEventListener(name,event=>{
   const point=event.changedTouches[0];trace(name,{x:point?.clientX,y:point?.clientY,target:event.target instanceof Element?event.target.tagName+'.'+event.target.className:String(event.target),cancelable:event.cancelable,defaultPrevented:event.defaultPrevented});
   queueMicrotask(()=>trace(name+'.after',{defaultPrevented:event.defaultPrevented}));
  },{capture:true,passive:true});
  for(const name of ['popstate','hashchange','pagehide','pageshow','beforeunload'])window.addEventListener(name,event=>trace(name,{persisted:event.persisted}));
  if(window.navigation)window.navigation.addEventListener('navigate',event=>trace('navigation.navigate',{destination:event.destination.url,navigationType:event.navigationType,userInitiated:event.userInitiated,canIntercept:event.canIntercept}));
  trace('document.init');
 });
 customer.on('framenavigated',frame=>{if(frame===customer.mainFrame())navigationTrace.push({type:'playwright.framenavigated',url:frame.url()});});
 const failures=[];
 for(const [name,page] of [['admin',admin],['customer',customer]]){
  page.on('pageerror',error=>failures.push(name+': '+error.message));
  page.on('response',r=>{if(r.status()>=400&&r.url().includes('/api/'))failures.push(name+' HTTP '+r.status()+' '+new URL(r.url()).pathname);});
 }
 try{
  await login(admin,credentials);await expect(admin.getByText('No hay conversaciones todavía.')).toBeVisible({timeout:30000});
  const panel=await options(admin,'Invitaciones al chat');await panel.getByRole('button',{name:'Generar enlace al chat'}).click();
  const link=panel.locator('code').filter({hasText:'#lead='});await expect(link).toBeVisible({timeout:30000});const guestLink=await link.textContent();assert.ok(guestLink.startsWith(base));
  await panel.getByRole('button',{name:'Cerrar',exact:true}).click();
  await customer.goto(guestLink);await expect(customer.getByPlaceholder('Mensaje',{exact:true})).toBeVisible({timeout:60000});
  const intro='Browser guest greeting';await send(customer,intro);await visibleMessage(admin,intro);
  await send(admin,'Browser administrator reply');await visibleMessage(customer,'Browser administrator reply');
  await customer.reload();await visibleMessage(customer,intro);await visibleMessage(customer,'Browser administrator reply');
  await admin.getByRole('button',{name:'Crear cuenta',exact:true}).click();
  const account=admin.getByRole('dialog',{name:'Crear cuenta para el invitado'});await account.getByLabel('Nombre o apodo del cliente').fill('Browser customer');
  await account.getByRole('button',{name:'Crear cuenta y conservar chat'}).click();await expect(account).toHaveCount(0,{timeout:30000});
  t.diagnostic('Actual desktop login, UI invitation, guest registration, account conversion, and authenticated bidirectional delivery passed.');

  // Mobile options must hide staff capabilities while retaining account actions.
  await customer.locator('.options-menu-button').tap();const mobileOptions=customer.getByRole('dialog',{name:'Opciones de Ratchet'});
  await expect(mobileOptions).toBeVisible();await expect(mobileOptions.getByRole('button',{name:/Agentes|Invitaciones al chat/})).toHaveCount(0);
  await expect(mobileOptions.getByRole('button',{name:'Activar notificaciones'})).toBeVisible();
  await mobileOptions.getByRole('button',{name:'Cerrar opciones'}).tap();
  await customer.getByRole('button',{name:'Abrir conversaciones'}).tap();await expect(customer.getByRole('navigation',{name:'Navegación principal'})).toBeVisible();
  assert.ok(await customer.evaluate(()=>document.documentElement.scrollWidth)<=390);
  await customer.getByRole('button',{name:'Cerrar menú'}).tap();
  const touch=await customerContext.newCDPSession(customer);
  await touch.send('Page.enable');
  touch.on('Page.frameRequestedNavigation',event=>navigationTrace.push({type:'cdp.frameRequestedNavigation',...event}));
  touch.on('Page.frameScheduledNavigation',event=>navigationTrace.push({type:'cdp.frameScheduledNavigation',...event}));
  const swipe=async(from,to)=>{
   await touch.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x:from,y:350}]});
   for(let step=1;step<=4;step++)await touch.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:from+(to-from)*step/4,y:350}]});
   await touch.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
  };
  navigationTrace.push({type:'test.before-open-swipe',url:customer.url(),snapshot:await customer.evaluate(()=>({state:history.state,length:history.length,shellTouchAction:getComputedStyle(document.querySelector('.shell')).touchAction}))});
  await swipe(10,220);await expect(customer.getByRole('navigation',{name:'Navegación principal'})).toBeVisible();
  await swipe(240,80);await expect(customer.getByRole('navigation',{name:'Navegación principal'})).toBeHidden();
  await touch.detach();
  await customer.setViewportSize({width:390,height:420});await send(customer,'Mobile keyboard viewport message');await visibleMessage(admin,'Mobile keyboard viewport message');
  const composerBox=await customer.getByPlaceholder('Mensaje',{exact:true}).boundingBox();assert.ok(composerBox&&composerBox.y+composerBox.height<=421);
  await customer.screenshot({path:resolve(output,'mobile-chat.png'),fullPage:true});await customer.setViewportSize({width:390,height:844});

  // The browser creates, encrypts, uploads, receives, decrypts, and downloads real bytes.
  await downloadAttachments(customer,admin,'Browser multiple attachments',[
   {name:'browser-photo-a.png',mimeType:'image/png',buffer:png},
   {name:'browser-photo-b.png',mimeType:'image/png',buffer:Buffer.concat([png,Buffer.alloc(400*1024-png.length)])},
   {name:'browser-document.pdf',mimeType:'application/pdf',buffer:pdf},
  ]);
  await admin.reload();await visibleMessage(admin,'Browser multiple attachments');
  t.diagnostic('Three actual attachments uploaded together and downloaded by the recipient with identical SHA-256 hashes.');

  const appearance=await options(admin,'Apariencia');await expect(appearance.locator('.wallpaper-upload input')).toBeAttached();
  const wallpaper=Buffer.concat([png,Buffer.alloc(400*1024-png.length)]);
  await appearance.locator('.wallpaper-upload input').setInputFiles({name:'browser-wallpaper.png',mimeType:'image/png',buffer:wallpaper});
  await expect(admin.locator('.messages')).toHaveClass(/wallpaper-custom/,{timeout:60000});await appearance.getByRole('button',{name:'Cerrar',exact:true}).click();
  await expect(customer.locator('.messages')).toHaveClass(/wallpaper-custom/,{timeout:60000});await customer.reload();
  await expect(customer.locator('.messages')).toHaveClass(/wallpaper-custom/,{timeout:60000});
  await expect.poll(()=>customer.locator('.messages').evaluate(el=>el.style.getPropertyValue('--chat-wallpaper-image')),{timeout:60000}).toContain('blob:');
  const rendered=await customer.locator('.messages').evaluate(async (el,original)=>{
   const raw=el.style.getPropertyValue('--chat-wallpaper-image'),url=JSON.parse(raw.slice(4,-1));
   const pixels=async source=>{const image=new Image();image.src=source;await image.decode();const canvas=document.createElement('canvas');canvas.width=image.naturalWidth;canvas.height=image.naturalHeight;const context=canvas.getContext('2d');context.drawImage(image,0,0);return{width:canvas.width,height:canvas.height,pixels:[...context.getImageData(0,0,canvas.width,canvas.height).data]};};
   return{actual:await pixels(url),expected:await pixels('data:image/png;base64,'+original)};
  },png.toString('base64'));assert.ok(rendered.actual.width>0);assert.deepEqual(rendered.actual,rendered.expected);
  await admin.screenshot({path:resolve(output,'desktop-files-wallpaper.png'),fullPage:true});await customer.screenshot({path:resolve(output,'mobile-wallpaper.png'),fullPage:true});
  t.diagnostic('Account wallpaper reached the mobile customer, rendered identical pixels and dimensions to the original PNG, and survived reload.');

  await adminContext.setOffline(true);await send(customer,'Durable message while recipient offline');
  await expect(customer.locator('.bubble.own footer').filter({hasText:/pendiente|enviando|no enviado/})).toHaveCount(0,{timeout:60000});
  await adminContext.setOffline(false);await admin.reload();await visibleMessage(admin,'Durable message while recipient offline');
  await send(admin,'Message after reconnect');await visibleMessage(customer,'Message after reconnect');
  await customerContext.setOffline(true);await send(customer,'Queued mobile message while offline');await customerContext.setOffline(false);
  await visibleMessage(admin,'Queued mobile message while offline');await customer.reload();await visibleMessage(customer,'Queued mobile message while offline');
  await expect(admin.locator('.error-banner')).toHaveCount(0);await expect(customer.locator('.error-banner')).toHaveCount(0);
  assert.equal(failures.filter(x=>!x.includes('HTTP 401 /api/v1/sessions/current')).filter(x=>!x.includes('HTTP 404 /api/v1/appearance/')).length,0,failures.join('\n'));
  t.diagnostic('Desktop and mobile options, constrained viewport, recipient offline recovery, sender offline queue, reconnect, and reload passed.');
 }catch(error){
  await writeFile(resolve(output,'navigation-trace.json'),JSON.stringify(navigationTrace,null,2));
  t.diagnostic('MOBILE NAVIGATION TRACE '+JSON.stringify(navigationTrace,null,2));
  for(const [name,page] of [['admin',admin],['customer',customer]]){await page.screenshot({path:resolve(output,name+'-failure.png'),fullPage:true}).catch(()=>{});t.diagnostic(name+' URL '+page.url());t.diagnostic((await page.locator('body').innerText().catch(()=>'' )).slice(-8000));}
  t.diagnostic(failures.join('\n'));throw error;
 }finally{await browser.close();}
});
