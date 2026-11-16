// Shared helpers
const $ = (s,el=document)=>el.querySelector(s);
const $$ = (s,el=document)=>[...el.querySelectorAll(s)];
async function api(url,opt){const r=await fetch(url,opt);let j;try{j=await r.json()}catch(e){j={ok:false,error:'bad response'}}return j;}
async function apiPost(url,body){return api(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});}
function fmtTime(t){if(!t)return'—';const d=new Date(t*1000);return d.toLocaleString();}
function el(tag,cls,html){const e=document.createElement(tag);if(cls)e.className=cls;if(html!=null)e.innerHTML=html;return e;}
function toast(msg,kind){let t=el('div','alert '+(kind||'ok'),msg);t.style.cssText='position:fixed;right:20px;bottom:20px;z-index:99;box-shadow:0 8px 30px #000';document.body.appendChild(t);setTimeout(()=>t.remove(),3500);}
function sev(s){return `<span class="badge b-${(s||'low').toLowerCase()}">${s||'-'}</span>`;}
function lbl(v){return v==1||v=='abnormal'?'<span class="badge b-abn">ABNORMAL</span>':'<span class="badge b-normal">normal</span>';}

async function refreshTop(){
  const h=await api('/api/health'); if(!h.ok)return;
  const s=h.system||{};
  $('#chip-cpu').textContent='CPU '+(s.cpu_percent??'—')+'%';
  $('#chip-ram').textContent='RAM '+(s.ram_percent??'—')+'%';
  $('#chip-model').textContent='model: '+(h.active_model||'none');
  const c=$('#chip-cow'); const cw=h.cowrie||{};
  c.textContent='Cowrie '+(cw.running?'up':'down'); c.className='chip '+(cw.running?'ok':'');
}
if(document.querySelector('#topstatus')){refreshTop();setInterval(refreshTop,5000);}
