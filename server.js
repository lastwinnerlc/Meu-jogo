// Last Winner LC - servidor online (sem dependências). Node 18+.
// Variáveis: PORT, ADMIN_KEY (obrigatória p/ painel), DATA_FILE (onde salvar os dados)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,ADMIN=process.env.ADMIN_KEY||'',DATA=process.env.DATA_FILE||path.join(__dirname,'data.json');
let db={},toks={},acct={},bans={},fails={};
try{const j=JSON.parse(fs.readFileSync(DATA,'utf8'));db=j.db||{};toks=j.toks||{};acct=j.acct||{};bans=j.bans||{}}catch(e){}
let dirty=false;
setInterval(()=>{if(dirty){dirty=false;fs.writeFile(DATA, JSON.stringify({db, toks, acct, bans}),()=>{})}},3000);

function atualizarPerfilJogador(id, novosDados) {
  if (acct && acct[id]) {
    acct[id] = { ...acct[id], ...novosDados };
    dirty = true;
    return true;
  }
  return false;
}

const conns=new Map(),pres=new Map(),dp=new Set();
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const isAdm=k=>!!ADMIN&&typeof k=='string'&&k.length==ADMIN.length&&crypto.timingSafeEqual(Buffer.from(k),Buffer.from(ADMIN));
// regras de acesso: op 'r' (ler) ou 'w' (escrever)
function can(op,p,uid,adm){if(adm)return true;const s=p.split('/'),c=s[0];
 if(c=='users')return op=='r'||s[1]==uid;
 if(c=='support')return s[1]==uid;
 if(c=='grants'||c=='mods')return op=='r'&&s[1]==uid;
 if(c=='evt')return op=='r';
 if(c=='clans'||c=='cpts'||c=='acc')return true;
 if(c=='data'&&s[1]=='users')return s[2]==uid;
 return false}
function auth(uid,tok){if(typeof uid!='string'||typeof tok!='string'||uid.length<8||uid.length>64||tok.length<8||tok.length>128)return false;
 if(bans[uid])return 'ban';const h=sha(tok);let a=toks[uid];if(typeof a=='string')a=toks[uid]=[a];if(!a||!a.length){toks[uid]=[h];dirty=true;return true}return a.includes(h)}
const send=(c,m)=>{try{c.res.write('data: '+JSON.stringify(m)+'\n\n')}catch(e){}};
function notify(p){for(const c of conns.values())if(c.subs.has(p))send(c,{t:'doc',path:p,exists:p in db,data:db[p]})}
setInterval(()=>{if(!dp.size)return;const m={};dp.forEach(k=>{if(pres.has(k))m[k]=pres.get(k)});dp.clear();for(const c of conns.values())send(c,{t:'pb',m})},80);
setInterval(()=>{for(const c of conns.values())try{c.res.write(': ka\n\n')}catch(e){}},20000);
const cors={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,x-admin','Access-Control-Allow-Methods':'GET,POST,OPTIONS'};
const json=(res,code,o)=>{res.writeHead(code,Object.assign({'Content-Type':'application/json'},cors));res.end(JSON.stringify(o))};
function body(req,cb){let b='';req.on('data',d=>{b+=d;if(b.length>400000)req.destroy()});req.on('end',()=>{try{cb(JSON.parse(b||'{}'))}catch(e){cb(null)}})}
function rpc(b,res){const a_=b&&auth(b.uid,b.tok);if(a_!==true)return json(res,403,{ok:0,err:a_==='ban'?'ban':'auth'});const adm=isAdm(b.adm),uid=b.uid;
 const col=x=>String(x||'').split('/')[0];
 switch(b.op){
 case'who':return json(res,200,{ok:1,owner:adm});
 case'get':{const p=String(b.path||'');if(!can('r',p,uid,adm))return json(res,403,{ok:0,err:'rule'});return json(res,200,{ok:1,exists:p in db,data:db[p]})}
    case 'grant':
      if (!adm) return json(res, 403, { ok: 0, err: 'admin' });
      if (!acct[b.uid]) return json(res, 404, { ok: 0, err: 'not_found' });
      
      if (b.coins !== undefined) {
        acct[b.uid].coins = (acct[b.uid].coins || 0) + Number(b.coins);
        acct[b.uid].moedas = (acct[b.uid].moedas || 0) + Number(b.coins);
      }
      if (b.gems !== undefined) {
        acct[b.uid].gems = (acct[b.uid].gems || 0) + Number(b.gems);
        acct[b.uid].diamantes = (acct[b.uid].diamantes || 0) + Number(b.gems);
      }
      if (b.nivel !== undefined) {
        acct[b.uid].nivel = Number(b.nivel);
      }
      
      dirty = true;
      return json(res, 200, { ok: 1 });

 case'set':{const p=String(b.path||'');if(!can('w',p,uid,adm)||typeof b.data!='object'||!b.data)return json(res,403,{ok:0,err:'rule'});db[p]=b.data;dirty=true;notify(p);return json(res,200,{ok:1})}
 case'del':{const p=String(b.path||'');if(!can('w',p,uid,adm))return json(res,403,{ok:0,err:'rule'});delete db[p];dirty=true;notify(p);return json(res,200,{ok:1})}
 case'query':{const c=col(b.col);if(!can('r',c+'/*',uid,adm)&&!can('r',c+'/'+uid,uid,adm))return json(res,403,{ok:0,err:'rule'});
  const w=b.w,docs=[];for(const k of Object.keys(db)){const s=k.split('/');if(s.length!=2||s[0]!=c)continue;if(w&&!(w[1]=='=='&&db[k][w[0]]===w[2]))continue;if(!can('r',k,uid,adm))continue;docs.push({id:s[1],data:db[k]})}
  return json(res,200,{ok:1,docs})}
 case'sub':case'unsub':{const cn=conns.get(b.cid);if(!cn||cn.uid!=uid)return json(res,409,{ok:0,err:'cid'});const p=String(b.path||'');
  if(b.op=='unsub'){cn.subs.delete(p);return json(res,200,{ok:1})}
  if(!can('r',p,uid,adm))return json(res,403,{ok:0,err:'rule'});cn.subs.add(p);send(cn,{t:'doc',path:p,exists:p in db,data:db[p]});return json(res,200,{ok:1})}
 case'pres':{const cn=conns.get(b.cid);if(!cn||cn.uid!=uid||!b.p||typeof b.p!='object')return json(res,409,{ok:0,err:'cid'});const o=pres.get(b.cid)||{};
  for(const k of Object.keys(b.p)){if(b.p[k]===null)delete o[k];else o[k]=b.p[k]}pres.set(b.cid,o);dp.add(b.cid);return json(res,200,{ok:1})}
 }json(res,400,{ok:0,err:'op'})}
function account(b,res){if(!b||typeof b.nick!='string'||typeof b.pw!='string')return json(res,400,{ok:0,err:'in'});const nick=b.nick.trim().slice(0,14),nl=nick.toLowerCase();
 if(b.op=='reg'){const a=auth(b.uid,b.tok);if(a!==true)return json(res,403,{ok:0,err:a==='ban'?'ban':'auth'});if(nick.length<3||b.pw.length<4)return json(res,200,{ok:0,err:'in'});
  const ex=acct[nl];if(ex&&ex.uid!=b.uid)return json(res,200,{ok:0,err:'nick'});
  for(const k of Object.keys(db))if(k.startsWith('users/')&&db[k].nl==nl&&k!='users/'+b.uid)return json(res,200,{ok:0,err:'nick'});
  for(const k of Object.keys(acct))if(acct[k].uid==b.uid&&k!=nl)delete acct[k];
  const salt=crypto.randomBytes(16);acct[nl]={uid:b.uid,n:nick,s:salt.toString('hex'),h:crypto.scryptSync(b.pw,salt,32).toString('hex')};dirty=true;return json(res,200,{ok:1})}
 if(b.op=='login'){const f=fails[nl]||(fails[nl]={n:0,t:Date.now()});if(Date.now()-f.t>6e5)f.n=0;if(f.n>=5)return json(res,429,{ok:0,err:'wait'});
  const a=acct[nl];let ok=false;if(a){try{ok=crypto.timingSafeEqual(crypto.scryptSync(b.pw,Buffer.from(a.s,'hex'),32),Buffer.from(a.h,'hex'))}catch(e){}}
  if(!ok){f.n++;f.t=Date.now();return json(res,200,{ok:0,err:'pw'})}f.n=0;if(bans[a.uid])return json(res,403,{ok:0,err:'ban'});
  const tok=crypto.randomBytes(24).toString('hex'),t=toks[a.uid]||[];t.push(sha(tok));toks[a.uid]=t.slice(-5);dirty=true;
  return json(res,200,{ok:1,uid:a.uid,tok,nick:a.n,save:db['data/users/'+a.uid+'/save']||null})}
 json(res,400,{ok:0,err:'op'})}
function admin(b,res,key){if(!isAdm(key)||!b)return json(res,403,{ok:0});
 switch(b.op){
 case'threads':return json(res,200,{ok:1,t:Object.keys(db).filter(k=>k.startsWith('support/')).map(k=>{const d=db[k],m=d.msgs||[];return{uid:k.slice(8),n:d.n,pid:d.pid,c:m.length,last:(m[m.length-1]||{}).x||''}})});
 case'thread':return json(res,200,{ok:1,d:db['support/'+b.uid]||{msgs:[]}});
 case'reply':{const k='support/'+String(b.uid);const d=db[k]||(db[k]={msgs:[]});d.msgs=(d.msgs||[]).concat([{f:'s',t:Date.now(),x:String(b.text||'').slice(0,300)}]).slice(-30);dirty=true;notify(k);return json(res,200,{ok:1})}
 case'users':return json(res,200,{ok:1,u:Object.keys(db).filter(k=>k.startsWith('users/')).map(k=>{const uid=k.slice(6);return Object.assign({uid,banned:!!bans[uid],mod:db['mods/'+uid]},db[k])})});
 case'event_get':return json(res,200,{ok:1,e:db['evt/current']||null});
 case'event':{const h=Math.min(720,Math.max(.1,+b.h||24));db['evt/current']={id:Date.now().toString(36),t:String(b.t||'Evento').slice(0,40),x:String(b.x||'').slice(0,120),dm:+b.dm||1,sp:+b.sp||1,cx:+b.cx||1,xx:+b.xx||1,until:Date.now()+h*36e5,g:{c:+b.gc||0,d:+b.gd||0}};dirty=true;notify('evt/current');return json(res,200,{ok:1})}
 case'event_stop':{delete db['evt/current'];dirty=true;notify('evt/current');return json(res,200,{ok:1})}
 case'mods':{const k='mods/'+String(b.uid);db[k]={dm:Math.min(10,Math.max(.1,+b.dm||1)),sp:Math.min(3,Math.max(.3,+b.sp||1))};dirty=true;notify(k);return json(res,200,{ok:1})}
 case'ban':{const u=String(b.uid);if(b.v){bans[u]=1;for(const c of conns.values())if(c.uid==u){try{c.res.end()}catch(e){}}}else delete bans[u];dirty=true;return json(res,200,{ok:1})}
 case'grant':{const k='grants/'+String(b.uid),o=db[k]||{nivel:0};db[k]={nivel:+b.nivel||0,coins:+b.coins||0,gems:+b.gems||0,skins:Array.isArray(b.skins)?b.skins:[]};if(acct[String(b.uid)]){acct[String(b.uid)].nivel=+b.nivel;}dirty=true;notify(k);return json(res,200,{ok:1})}




 case'online':return json(res,200,{ok:1,n:conns.size,p:pres.size});
 }json(res,400,{ok:0})}
const ADMIN_HTML=`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Admin - Last Winner LC</title>
<style>body{font:14px system-ui;background:#14111c;color:#eee;margin:0;padding:12px}button,input{font:inherit;padding:6px 10px;margin:2px;border-radius:6px;border:1px solid #555;background:#241d33;color:#eee}.r{background:#241d33;padding:8px;margin:6px 0;border-radius:8px}.s{color:#7ab6ff}</style>
<h2>Painel do dono</h2><div><input id=k type=password placeholder="ADMIN_KEY"><button onclick="go()">Entrar</button> <span id=o></span></div><div id=m></div>
<script>
let K='';const $=i=>document.getElementById(i);
async function api(b){const r=await fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json','x-admin':K},body:JSON.stringify(b)});return r.json()}
function esc(t){return String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function go(){K=$('k').value;const o=await api({op:'online'});if(!o.ok){$('o').textContent='Chave inválida';return}$('o').textContent='Conectados: '+o.n;show()}
async function show(){const t=await api({op:'threads'}),u=await api({op:'users'}),ev=await api({op:'event_get'}),e=ev.e;
$('m').innerHTML='<h3>Evento atual</h3>'+(e&&e.until>Date.now()?'<div class=r><b>'+esc(e.t)+'</b> — '+esc(e.x||'')+'<br>dano x'+(e.dm||1)+' · velocidade x'+(e.sp||1)+' · moedas x'+(e.cx||1)+' · XP x'+(e.xx||1)+'<br><button onclick="stopEv()">Encerrar evento</button></div>':'<i>Nenhum</i>')+
'<div class=r><b>Novo evento</b><br><input id=et placeholder="Título"><input id=ex placeholder="Texto"><br>Horas <input id=eh value=24 size=3> Dano x<input id=edm value=1 size=3> Vel x<input id=esp value=1 size=3> Moedas x<input id=ecx value=1 size=3> XP x<input id=exx value=1 size=3><br>Brinde: moedas <input id=egc value=0 size=5> diamantes <input id=egd value=0 size=4><br><button onclick="pubEv()">Publicar evento</button></div>'+
'<h3>Jogadores</h3>'+(u.u.map(x=>'<div class=r><b>'+esc(x.n)+'</b> ID '+esc(x.pid)+' · nível '+(x.lv||1)+' · abates '+(x.k||0)+(x.banned?' · <b style="color:#f66">BANIDO</b>':'')+(x.mod?' · dano x'+(x.mod.dm||1)+' vel x'+(x.mod.sp||1):'')+'<br><button onclick="gr(\\''+x.uid+'\\')">Presente</button><button onclick="md(\\''+x.uid+'\\')">Dano/Velocidade</button><button onclick="bn(\\''+x.uid+'\\','+(x.banned?0:1)+')">'+(x.banned?'Desbanir':'Banir')+'</button></div>').join('')||'<i>Nenhum</i>')+
'<h3>Mensagens de suporte</h3>'+(t.t.map(x=>'<div class=r><b>'+esc(x.n||'?')+'</b> (ID '+esc(x.pid||'?')+') · '+x.c+' msgs<br>'+esc(x.last)+'<br><button onclick="op(\\''+x.uid+'\\')">Abrir / responder</button></div>').join('')||'<i>Nenhuma</i>')+'<div id=th></div>'}
async function pubEv(){await api({op:'event',t:$('et').value,x:$('ex').value,h:+$('eh').value,dm:+$('edm').value,sp:+$('esp').value,cx:+$('ecx').value,xx:+$('exx').value,gc:+$('egc').value,gd:+$('egd').value});show()}
async function stopEv(){await api({op:'event_stop'});show()}
async function bn(uid,v){if(v&&!confirm('Banir este jogador?'))return;await api({op:'ban',uid,v});show()}
async function md(uid){const a=prompt('Multiplicador de dano (1 = normal, máx 10)','1'),b=prompt('Multiplicador de velocidade (1 = normal, máx 3)','1');if(a===null||b===null)return;await api({op:'mods',uid,dm:+a,sp:+b});show()}
async function gr(uid){
  const n=prompt('Nível?','1');
  const c=prompt('Moedas?','0');
  const g=prompt('Diamantes?','0');
  const s=prompt('Skins (ex: 0.5,1.5) ou vazio','');
  if(c===null||g===null||n===null)return;
  await api({op:'grant',uid:uid,coins:+c,gems:+g,nivel:+n,skins:s?s.split(',').map(x=>x.trim()):[]});
  alert('Presente e nível enviados com sucesso!');
  show();
}

async function op(uid){const d=(await api({op:'thread',uid})).d;$('th').innerHTML='<h3>Conversa</h3>'+(d.msgs||[]).map(x=>'<div class=r><span class=s>'+(x.f=='s'?'Suporte':'Jogador')+':</span> '+esc(x.x)+'</div>').join('')+'<input id=tx style="width:70%" placeholder="Resposta"><button onclick="rp(\\''+uid+'\\')">Enviar</button>'}
async function rp(uid){await api({op:'reply',uid,text:$('tx').value});op(uid)}
</script>`;
http.createServer((req,res)=>{const u=new URL(req.url,'http://x');
 if(req.method=='OPTIONS'){res.writeHead(204,cors);return res.end()}
 if(u.pathname=='/events'){const cid=u.searchParams.get('cid'),uid=u.searchParams.get('uid');if(!cid||auth(uid,u.searchParams.get('tok')||'')!==true){res.writeHead(403,cors);return res.end()}
  res.writeHead(200,Object.assign({'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'},cors));
  const c={res,uid,subs:new Set()};conns.set(cid,c);send(c,{t:'hello'});const m={};pres.forEach((v,k)=>m[k]=v);send(c,{t:'pb',m});
  req.on('close',()=>{conns.delete(cid);pres.delete(cid);for(const o of conns.values())send(o,{t:'pd',id:cid})});return}
 if(u.pathname=='/auth'&&req.method=='POST')return body(req,b=>account(b,res));
 if(u.pathname=='/rpc'&&req.method=='POST')return body(req,b=>rpc(b,res));
 if(u.pathname=='/admin/api'&&req.method=='POST')return body(req,b=>admin(b,res,req.headers['x-admin']));
 if(u.pathname=='/admin'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(ADMIN_HTML)}
 if(u.pathname=='/health'){res.writeHead(200,cors);return res.end('ok')}
 if(u.pathname=='/'||u.pathname=='/index.html'){fs.readFile(path.join(__dirname,'public','index.html'),'utf8',(e,h)=>{if(e){res.writeHead(500);return res.end('index.html não encontrado')}
  const proto=(req.headers['x-forwarded-proto']||'http').split(',')[0],origin=proto+'://'+req.headers.host;
  res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});res.end(h.replace('__LW_SERVER__',origin))});return}
 res.writeHead(404);res.end('404')}).listen(PORT,()=>console.log('Last Winner LC online na porta '+PORT+(ADMIN?'':' (ATENÇÃO: defina ADMIN_KEY)')));
