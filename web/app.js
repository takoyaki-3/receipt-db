const API = '';
const AUTH_BASE = 'https://takoyaki3-auth.web.app/';
const params = new URLSearchParams(location.search);
let jwt = (params.get('jwt') || '').trim();
if (params.has('jwt')) history.replaceState(null, '', location.pathname + location.hash);

const $ = selector => document.querySelector(selector);
const state = { receipts: [], month: new Date(), stream: null, active: null };
const yen = new Intl.NumberFormat('ja-JP', { style: 'currency', currency: 'JPY', maximumFractionDigits: 0 });
const escapeHtml = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const login = () => location.replace(`${AUTH_BASE}?r=${encodeURIComponent(location.origin + location.pathname)}`);
const toast = message => { const el=$('#toast'); el.textContent=message; el.classList.add('show'); clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.classList.remove('show'),2800); };

async function api(path, options={}) {
  const result = await fetch(API + path, {...options, headers:{Authorization:`Bearer ${jwt}`,'Content-Type':'application/json',...(options.headers||{})}});
  let body={}; try { body=await result.json(); } catch {}
  if (result.status===401) { jwt=''; login(); throw new Error('認証が必要です'); }
  if (!result.ok) throw new Error(body.message || `API error (${result.status})`);
  return body;
}

function receiptDate(receipt) {
  const raw=receipt.purchasedAt || receipt.createdAt;
  const match=String(raw).match(/(20\d{2})\s*(?:年|[\/.-])\s*(\d{1,2})\s*(?:月|[\/.-])\s*(\d{1,2})/);
  if (match) return new Date(+match[1],+match[2]-1,+match[3]);
  const date=new Date(raw); return Number.isNaN(date.getTime()) ? new Date(receipt.createdAt) : date;
}
const inSelectedMonth = receipt => { const d=receiptDate(receipt); return d.getFullYear()===state.month.getFullYear() && d.getMonth()===state.month.getMonth(); };

function render() {
  const selected=state.receipts.filter(inSelectedMonth);
  $('#month-label').textContent=`${state.month.getFullYear()}年 ${state.month.getMonth()+1}月`;
  $('#stat-total').textContent=yen.format(selected.reduce((sum,r)=>sum+Number(r.total||0),0));
  $('#stat-count').innerHTML=`${selected.length}<small>枚</small>`;
  $('#stat-items').innerHTML=`${selected.reduce((sum,r)=>sum+Number(r.itemCount||0),0)}<small>点</small>`;
  const query=$('#search').value.trim().toLowerCase();
  const filtered=selected.filter(r=>!query || [r.storeName,r.category,...(r.items||[]).map(i=>i.name)].join(' ').toLowerCase().includes(query));
  $('#empty').hidden=state.receipts.length!==0;
  $('#receipt-list').innerHTML=filtered.map(r=>{
    const date=receiptDate(r); const names=(r.items||[]).slice(0,4).map(i=>i.name).join('、');
    return `<article class="receipt-row" data-id="${escapeHtml(r.receipt_id)}" tabindex="0">
      <div class="date-tile"><strong>${String(date.getDate()).padStart(2,'0')}</strong><span>${date.toLocaleDateString('en-US',{month:'short'}).toUpperCase()}</span></div>
      <div class="row-main"><h3>${escapeHtml(r.storeName||'店名未取得')}</h3><p>${escapeHtml(names||'品目を確認してください')}</p></div>
      <span class="category">${escapeHtml(r.category||'未分類')}</span>
      <div class="row-total"><strong>${yen.format(Number(r.total||0))}</strong><small>${Number(r.itemCount||0)}品目 →</small></div>
    </article>`;
  }).join('');
}

async function loadReceipts() {
  $('#loading').hidden=false;
  try { const body=await api('/receipts'); state.receipts=body.receipts||[]; $('#user-email').textContent=body.user||''; render(); }
  catch(error) { toast(error.message); }
  finally { $('#loading').hidden=true; }
}

async function openCamera() {
  if (!navigator.mediaDevices?.getUserMedia) { $('#file-input').click(); return; }
  try {
    state.stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1920},height:{ideal:2560}},audio:false});
    $('#camera-video').srcObject=state.stream; $('#camera-dialog').showModal();
  } catch { $('#file-input').click(); }
}
function closeCamera() { state.stream?.getTracks().forEach(track=>track.stop()); state.stream=null; $('#camera-dialog').close(); }
async function capturePhoto() {
  const video=$('#camera-video'), canvas=$('#camera-canvas');
  canvas.width=video.videoWidth; canvas.height=video.videoHeight;
  canvas.getContext('2d').drawImage(video,0,0); closeCamera();
  const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',.9)); if(blob) analyzeImage(blob);
}

async function optimizeImage(file) {
  const bitmap=await createImageBitmap(file); const max=1800; const scale=Math.min(1,max/Math.max(bitmap.width,bitmap.height));
  const canvas=document.createElement('canvas'); canvas.width=Math.round(bitmap.width*scale); canvas.height=Math.round(bitmap.height*scale);
  canvas.getContext('2d',{alpha:false}).drawImage(bitmap,0,0,canvas.width,canvas.height); bitmap.close();
  let quality=.88, blob;
  do { blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',quality)); quality-=.08; } while(blob.size>4_400_000 && quality>.48);
  if(blob.size>4_500_000) throw new Error('画像を十分に小さくできませんでした');
  return blob;
}
const toBase64 = blob => new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=reject;reader.readAsDataURL(blob);});
async function analyzeImage(file) {
  $('#processing-dialog').showModal();
  try {
    const image=await optimizeImage(file); const encoded=await toBase64(image);
    const body=await api('/receipts',{method:'POST',body:JSON.stringify({image:encoded,mimeType:'image/jpeg',fileName:file.name||'camera.jpg'})});
    state.receipts.unshift(body.receipt); render(); toast('レシートを記録しました'); $('#processing-dialog').close(); await openDetail(body.receipt.receipt_id);
  } catch(error) { toast(error.message); }
  finally { if($('#processing-dialog').open) $('#processing-dialog').close(); $('#file-input').value=''; }
}

function itemRow(item={name:'',quantity:1,unitPrice:'',price:''}) {
  return `<div class="item-row"><input data-field="name" aria-label="商品名" title="商品名" value="${escapeHtml(item.name)}"><input data-field="quantity" aria-label="数量" title="数量" type="number" min="0" step="0.01" value="${escapeHtml(item.quantity||1)}"><input data-field="unitPrice" aria-label="単価" title="単価" type="number" min="0" step="1" placeholder="単価" value="${escapeHtml(item.unitPrice??'')}"><input data-field="price" aria-label="金額" title="金額" type="number" min="0" step="1" placeholder="金額" value="${escapeHtml(item.price??'')}"><button class="remove-item" type="button" aria-label="品目を削除">×</button></div>`;
}
async function openDetail(id) {
  try {
    const {receipt:r}=await api(`/receipts/${encodeURIComponent(id)}`); state.active=r;
    $('#detail-content').innerHTML=`<div class="detail-grid">
      <div><img class="detail-image" src="${escapeHtml(r.imageUrl)}" alt="保存されたレシート画像"><p class="confidence">AI解析信頼度 ${escapeHtml(r.confidence??0)}%</p></div>
      <form id="receipt-form"><div class="form-grid">
        <div class="field wide"><label>店舗名</label><input name="storeName" value="${escapeHtml(r.storeName)}"></div>
        <div class="field"><label>購入日</label><input name="purchasedAt" value="${escapeHtml(r.purchasedAt)}"></div>
        <div class="field"><label>カテゴリー</label><select name="category">${['未分類','食費','日用品','交通','医療','趣味','仕事','その他'].map(x=>`<option ${r.category===x?'selected':''}>${x}</option>`).join('')}</select></div>
        <div class="field wide"><label>住所</label><input name="address" value="${escapeHtml(r.address)}"></div>
        <div class="field"><label>電話番号</label><input name="phone" value="${escapeHtml(r.phone)}"></div>
        <div class="field"><label>支払方法</label><input name="paymentMethod" value="${escapeHtml(r.paymentMethod)}"></div>
        <div class="field"><label>小計（円）</label><input name="subtotal" type="number" value="${escapeHtml(r.subtotal??'')}"></div>
        <div class="field"><label>税（円）</label><input name="tax" type="number" value="${escapeHtml(r.tax??'')}"></div>
        <div class="field wide"><label>合計（円）</label><input name="total" type="number" value="${escapeHtml(r.total??'')}"></div>
        <div class="field wide"><label>メモ</label><textarea name="note">${escapeHtml(r.note)}</textarea></div>
      </div><div class="items-head"><h3>購入品目</h3><button id="add-item" class="mini-button" type="button">＋ 品目を追加</button></div>
      <div id="item-editor">${(r.items||[]).map(itemRow).join('')}</div>
      <details class="raw-text"><summary>OCRで読み取った原文を表示</summary><pre>${escapeHtml(r.rawText||'原文はありません')}</pre></details>
      <div class="detail-actions"><button id="delete-receipt" class="danger-button" type="button">この記録を削除</button><button class="save-button" type="submit">変更を保存</button></div>
      </form></div>`;
    $('#detail-dialog').showModal();
  } catch(error) { toast(error.message); }
}
function closeDetail(){ $('#detail-dialog').close(); state.active=null; }
async function saveDetail(event) {
  event.preventDefault(); const form=event.target; const values=Object.fromEntries(new FormData(form));
  const items=[...form.querySelectorAll('.item-row')].map(row=>({name:row.querySelector('[data-field=name]').value,quantity:row.querySelector('[data-field=quantity]').value||1,unitPrice:row.querySelector('[data-field=unitPrice]').value||null,price:row.querySelector('[data-field=price]').value||null}));
  const payload={...values,subtotal:values.subtotal||null,tax:values.tax||null,total:values.total||null,items};
  try { const {receipt}=await api(`/receipts/${state.active.receipt_id}`,{method:'PUT',body:JSON.stringify(payload)}); const index=state.receipts.findIndex(r=>r.receipt_id===receipt.receipt_id); state.receipts[index]=receipt; render(); closeDetail(); toast('変更を保存しました'); }
  catch(error){toast(error.message)}
}
async function deleteReceipt() {
  if(!state.active || !confirm('このレシート画像と記録を削除しますか？')) return;
  try { await api(`/receipts/${state.active.receipt_id}`,{method:'DELETE'}); state.receipts=state.receipts.filter(r=>r.receipt_id!==state.active.receipt_id); render(); closeDetail(); toast('レシートを削除しました'); }
  catch(error){toast(error.message)}
}

$('#open-camera').addEventListener('click',openCamera); $('#close-camera').addEventListener('click',closeCamera); $('#take-photo').addEventListener('click',capturePhoto);
$('#file-input').addEventListener('change',event=>event.target.files[0]&&analyzeImage(event.target.files[0]));
$('#close-detail').addEventListener('click',closeDetail); $('#search').addEventListener('input',render);
$('#prev-month').addEventListener('click',()=>{state.month=new Date(state.month.getFullYear(),state.month.getMonth()-1,1);render()});
$('#next-month').addEventListener('click',()=>{state.month=new Date(state.month.getFullYear(),state.month.getMonth()+1,1);render()});
$('#receipt-list').addEventListener('click',event=>{const row=event.target.closest('.receipt-row');if(row)openDetail(row.dataset.id)});
$('#receipt-list').addEventListener('keydown',event=>{if((event.key==='Enter'||event.key===' ')&&event.target.matches('.receipt-row'))openDetail(event.target.dataset.id)});
$('#detail-content').addEventListener('submit',saveDetail);
$('#detail-content').addEventListener('click',event=>{if(event.target.id==='add-item')$('#item-editor').insertAdjacentHTML('beforeend',itemRow());if(event.target.matches('.remove-item'))event.target.closest('.item-row').remove();if(event.target.id==='delete-receipt')deleteReceipt()});
$('#logout').addEventListener('click',()=>{jwt='';login()});
$('#camera-dialog').addEventListener('cancel',event=>{event.preventDefault();closeCamera()});
if(jwt) loadReceipts(); else login();
