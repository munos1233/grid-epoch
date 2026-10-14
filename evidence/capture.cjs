const fs = require('fs');
const path = require('path');
const {chromium}=require('/Users/easonzhong/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const root=path.resolve(__dirname);
const manifest=process.env.RESUME ? JSON.parse(fs.readFileSync(path.join(root,'manifest.json'))) : [];
(async()=>{
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1560,height:1200},deviceScaleFactor:1.5});
 page.on('pageerror',e=>{throw e});
 await page.goto('http://127.0.0.1:8765');
 await page.waitForFunction(()=>document.querySelector('#members').children.length===4 && document.querySelector('#bench').textContent.includes('100 万台确认重算'));
 async function snap(file,title,expected){
  const body=await page.locator('body').innerText();
  for(const word of expected||[]) if(!body.includes(word)) throw new Error(file+' 缺少 '+word);
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:path.join(root,'screenshots',file+'.png'),fullPage:true});
  const status=await page.request.get('http://127.0.0.1:8765/api/status').then(r=>r.json());
  manifest.push({file:file+'.png',title,expected,status,result:await page.locator('#result').innerText()});
  fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify(manifest,null,2));
  console.log(file+' '+await page.locator('#result').innerText());
 }
 async function click(id,expected){
  const refreshed=page.waitForResponse(r=>r.url().endsWith('/api/audit')).catch(()=>null);
  const response=page.waitForResponse(r=>r.url().includes('/api/')&&r.request().method()==='POST');
  await page.locator('#'+id).click();
  const posted=await response;
  await page.waitForFunction(text=>document.querySelector('#result').textContent.includes(text),expected,{timeout:20000});
  // A successful action refreshes the tables and audit in sequence.
  if(posted.ok()) await refreshed;
  await page.waitForLoadState('networkidle');
 }
 const fill=async(id,text)=>page.locator('#'+id).fill(text);
 if (process.env.RESUME) {
  const status=await page.request.get('http://127.0.0.1:8765/api/status').then(r=>r.json());
  if(status.epoch!==1) throw Error('恢复截图时纪元不为1');
  await click('enroll','接入签名核对通过');
  await snap('16-sm9-enrollment','在册终端接入通过，页眉仍是纪元1',['接入签名核对通过']);
 } else {
 await snap('03-console-footer','重启后的本机基准页脚',['本机吞吐，不是端到端时延','236 / 216 / 118 字节','完成帧 62 字节']);
 const zones=await page.locator('#zones tr').allTextContents();
 if(zones.length!==3 || zones.some(t=>!t.includes('未下发')))throw Error('初始台区显示不正确');
 await snap('04-unpublished','发布前：三台区各四台，未下发',['尚未发布','42','43','44','未下发']);
 await fill('pw-a','值班甲');await fill('pw-b','值班乙');
 await click('publish','已发布纪元 1');
 await snap('05-published','纪元1：完全子树与三份SM2验签',['完全子树','236 字节 · SM2 通过','216 字节 · SM2 通过','118 字节 · SM2 通过']);
 await click('confirm','已确认 4 台');
 const members=await page.locator('#members tr').allTextContents();
 if(members.some(t=>!t.includes('已确认')))throw Error('未全部确认');
 await snap('06-confirm-all','台区42四台确认，43与44未下发',['已确认 4 台','完成帧 62 字节','未下发']);
 await fill('pw-b','故意填错');await click('restore','两份口令才能恢复主密钥');
 await snap('12-password-wrong','错一份口令：核对失败',['两份口令才能恢复主密钥']);
 await fill('pw-b','值班乙');await click('restore','两份口令核对通过');
 await snap('13-password-correct','两份口令核对通过',['两份口令核对通过']);
 await click('recover-epoch','纪元 1 的托管包已打开');
 await snap('14-epoch-escrow','纪元1托管打开，不返回随机数',['纪元 1 的托管包已打开']);
 await click('drop','已丢弃纪元 1 之前的随机数');
 await snap('15-drop-expired','当前仍是纪元1，没有更早纪元可丢',['已丢弃纪元 1 之前的随机数']);
 await click('enroll','接入签名核对通过');
 await snap('16-sm9-enrollment','在册终端接入通过，页眉仍是纪元1',['接入签名核对通过']);
 }
 await fill('withhold','1');await click('confirm','完成帧被拒绝');
 await snap('17-confirm-withheld','扣下序号1：确认失败不吊销',['完成帧被拒绝','明细缺序号 1','已确认 3 台','已吊销仍为 0','被扣下']);
 await fill('local','1');await click('revoke','已吊销台区 42 序号 1');
 await snap('18-revoke-sd','单台吊销：切换子集差',['子集差','已吊销台区 42 序号 1']);
 await click('watch','观察名单：');
 await snap('19-watch','观察名单只有未下发台区',['台区 43、44','不参与验签，也不是确认失败']);
 await fill('local','0');await fill('new-local','4');await click('replace','已换到序号 4');
 await snap('20-replace','换表：新设备与新叶子',['已换到序号 4','叶子']);
 await fill('local','4');await fill('new-local','5');await fill('new-zone','45');
 await click('transfer','已割接到台区 45 序号 5');
 await snap('21-transfer','割接到新台区45，使用新序号5',['已割接到台区 45 序号 5']);
 await fill('local','2');await click('destroy','档案已销毁');
 await snap('22-destroy','销毁：叶子保留，在册减少',['档案已销毁','保留','已销毁']);
 await click('lookup','已销毁');
 await snap('23-destroy-lookup','销毁后查询：结果行已销毁',['序号 2','已销毁']);
 await click('enroll','终端已销毁');
 await snap('24-destroy-enrollment-rejected','销毁后接入被拒绝',['终端已销毁']);
 await click('transfer','终端已销毁');
 await snap('25-destroy-transfer-rejected','销毁后割接被拒绝',['终端已销毁']);
 await click('reprovision','终端已销毁');
 await snap('26-destroy-reprovision-rejected','销毁后重新灌装被拒绝',['终端已销毁']);
 await click('archive','已归档');
 await snap('27-archive-audit','归档更早审计，热表留最新一条',['已归档','条更早的审计']);
 await click('gateway','管控密钥未轮换');
 await snap('28-revoke-gateway','网关换槽，管控密钥未轮换',['管控密钥未轮换']);
 await fill('local','3');await click('reprovision','已重新灌装');
 await snap('29-reprovision','在册终端重新灌装，管理种子一致',['已重新灌装','管理种子按台区管控密钥重新导出，与原先一致']);
 await fill('firmware','1');await click('recall','摘掉');
 await snap('30-recall-last','最后一步：召回固件1',['版本 1 摘掉','个批次','子集差覆盖']);
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
