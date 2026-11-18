"""
Live web dashboard (read-only) for watching the proxy work in real time.

Routes (registered by main before the upstream catch-all):
  GET /ui         — the HTML page
  GET /ui/events  — Server-Sent Events stream of catches + request pings
  GET /ui/stats   — JSON snapshot (used for the initial render)

Originals are masked unless ANONPROXY_UI_SHOW_ORIGINALS=true, so this endpoint is
not a full de-anonymization oracle by default.
"""
import asyncio
import json

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from . import events
from .config import config


def _mask(value: str) -> str:
    if config.UI_SHOW_ORIGINALS:
        return value
    n = len(value)
    if n <= 4:
        return value[0] + "…"
    keep = 2 if n <= 10 else 3
    return f"{value[:keep]}…{value[-2:]} ({n})"


def _serialize(e: dict) -> dict:
    if e.get("kind") == "catch":
        return {
            "id": e["id"], "kind": "catch", "ts": e["ts"], "source": e["source"],
            "type": e["type"], "original": _mask(e["original"]), "surrogate": e["surrogate"],
        }
    return e


async def events_stream(request: Request) -> StreamingResponse:
    try:
        after = int(request.headers.get("last-event-id")
                    or request.query_params.get("after") or 0)
    except ValueError:
        after = 0

    async def gen():
        last = after
        # Replay recent buffer first so a fresh tab isn't empty.
        for e in events.since(last):
            last = e["id"]
            yield f"id: {e['id']}\ndata: {json.dumps(_serialize(e))}\n\n"
        while True:
            if await request.is_disconnected():
                break
            for e in events.since(last):
                last = e["id"]
                yield f"id: {e['id']}\ndata: {json.dumps(_serialize(e))}\n\n"
            yield ": keepalive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def stats_json() -> JSONResponse:
    snap = events.snapshot()
    snap["recent"] = [_serialize(e) for e in snap["recent"]]
    snap["show_originals"] = config.UI_SHOW_ORIGINALS
    snap["verbose"] = config.UI_VERBOSE
    snap["context"] = config.CONTEXT_ID
    return JSONResponse(snap)


def page() -> HTMLResponse:
    return HTMLResponse(_PAGE)


_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llm-anon-proxy — live</title>
<style>
  :root{
    --bg:#0b0f17; --panel:#121826; --line:#1e2838; --txt:#e6edf3; --muted:#8b97a7;
    --orig:#f6c177; --surr:#7fd4a1; --accent:#6ea8fe;
  }
  *{box-sizing:border-box}
  body{margin:0;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
       background:var(--bg);color:var(--txt)}
  header{position:sticky;top:0;background:linear-gradient(180deg,#0d1320,#0b0f17);
         border-bottom:1px solid var(--line);padding:10px 16px;z-index:5}
  .title{font-weight:700;letter-spacing:.5px}
  .title b{color:var(--accent)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;
       background:#f85149;vertical-align:middle}
  .dot.live{background:#3fb950;box-shadow:0 0 8px #3fb950}
  .sub{color:var(--muted);font-size:12px;margin-top:3px}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
  .chip{padding:2px 8px;border:1px solid var(--line);border-radius:12px;font-size:11px;
        background:#0e1522}
  .chip b{font-weight:700}
  main{padding:8px 0 40px}
  .row{display:grid;grid-template-columns:72px 92px 110px 1fr 16px 1fr;gap:10px;
       align-items:baseline;padding:4px 16px;border-bottom:1px solid #141b28}
  .row:hover{background:#0e1522}
  .row.req{grid-template-columns:72px 1fr;color:var(--muted);font-style:italic;
           background:#0a0e16}
  .ts{color:#5a6778}
  .src{color:#9db3d0;font-size:11px;text-transform:uppercase;letter-spacing:.3px}
  .type{font-weight:700;font-size:11px;padding:1px 7px;border-radius:5px;
        display:inline-block;text-align:center;white-space:nowrap}
  .orig{color:var(--orig);word-break:break-all}
  .arrow{color:#48566a}
  .surr{color:var(--surr);word-break:break-all}
  .empty{color:var(--muted);text-align:center;padding:40px}
  .banner{background:#3a1d1d;color:#ffb4a9;border-bottom:1px solid #5a2a2a;
          padding:6px 16px;font-size:12px}
  footer{position:fixed;bottom:0;left:0;right:0;background:#0b0f17;
         border-top:1px solid var(--line);padding:6px 16px;font-size:11px;color:var(--muted)}
  label{cursor:pointer}
</style>
</head>
<body>
<header>
  <div class="title"><span id="dot" class="dot"></span><b>llm-anon-proxy</b> — Claude Code More Anonymous! · live activity</div>
  <div class="sub">context <span id="ctx">…</span> · <span id="reqs">0</span> requests ·
       <span id="total">0</span> values caught · <span id="notices" style="color:#ff6b6b"></span><label><input type="checkbox" id="auto" checked> follow</label></div>
  <div class="chips" id="chips"></div>
</header>
<div id="banner"></div>
<main id="log"><div class="empty" id="empty">waiting for traffic… run Claude Code through the proxy</div></main>
<footer><b style="color:#7fd4a1">anonymized</b> = values hidden in the outgoing request · <b style="color:#f6c177">restored</b> = surrogates turned back to real values in the reply · green column = what left the machine · originals are <span id="maskmode">masked</span><span id="verbose"></span> · /ui</footer>
<script>
const log=document.getElementById('log'), chipsEl=document.getElementById('chips');
const dot=document.getElementById('dot'), auto=document.getElementById('auto');
const COLORS={IP_ADDRESS:'#f98181',CIDR:'#f98181',DOMAIN:'#f6a560',HOSTNAME:'#ffd479',
  EMAIL:'#79d0ff',USERNAME:'#79d0ff',PERSON:'#f392d0',ORGANIZATION:'#c58bf2',
  KEYWORD:'#b6e36b',CREDENTIAL:'#ff6b6b',TOKEN:'#ff8f6b',HASH:'#ffb36b',PATH:'#6be3c0',
  PESEL:'#f392d0',NIP:'#f392d0',REGON:'#f392d0',
  MAC_ADDRESS:'#f6a560',URL:'#79a9ff',ENCODED_B64:'#9aa5ff',ENCODED_B32:'#9aa5ff',
  ENCODED_HEX:'#9aa5ff',URL_ENCODED:'#9aa5ff',JSON_ESCAPED:'#9aa5ff',OTHER:'#9aa'};
const stats={}; let reqs=0, total=0, notices=0, empty=document.getElementById('empty');
function color(t){return COLORS[t]||'#9aa'}
function fmtTs(s){const d=new Date(s*1000);return d.toLocaleTimeString([], {hour12:false})}
function renderChips(){chipsEl.innerHTML=Object.entries(stats).sort((a,b)=>b[1]-a[1])
  .map(([t,n])=>`<span class="chip" style="border-color:${color(t)}55">
     <b style="color:${color(t)}">${t.toLowerCase()}</b> ${n}</span>`).join('');
  document.getElementById('total').textContent=total;
  document.getElementById('reqs').textContent=reqs;
  document.getElementById('notices').textContent=notices?('⚠ '+notices+' un-anonymized · '):'';}
function trim(){while(log.children.length>600)log.removeChild(log.firstChild);}
const _seen=new Set();
function add(e){
  if(e&&e.id!=null){if(_seen.has(e.id))return;_seen.add(e.id);}  // dedup snapshot vs stream replay
  if(empty){empty.remove();empty=null;}
  const div=document.createElement('div');
  if(e.kind==='request'){
    div.className='row req';
    const a=e.anon||0, an=e.anon_new||0, r=e.restored||0;
    div.innerHTML=`<span class="ts">${fmtTs(e.ts)}</span>
      <span title="anonymized = values hidden in the request sent upstream (new = first seen this session); restored = surrogates turned back into real values in the reply">↳ ${escapeHtml(e.model||'?')} · <b style="color:#7fd4a1">anonymized ${a}</b> (${an} new) · <b style="color:#f6c177">restored ${r}</b></span>`;
    reqs++;
  }else if(e.kind==='notice'){
    div.className='row';
    div.innerHTML=`<span class="ts">${fmtTs(e.ts)}</span>
      <span class="type" style="background:#ff6b6b22;color:#ff6b6b;border:1px solid #ff6b6b55">UNANON</span>
      <span class="orig" style="color:#ff9f9f">⚠ ${escapeHtml(e.message)} ${e.detail?('['+escapeHtml(e.detail)+']'):''}</span>`;
    notices++;
  }else{
    const c=color(e.type);
    div.className='row';
    div.innerHTML=`<span class="ts">${fmtTs(e.ts)}</span>
      <span class="src">${e.source}</span>
      <span class="type" style="background:${c}22;color:${c};border:1px solid ${c}55">${e.type}</span>
      <span class="orig">${escapeHtml(e.original)}</span>
      <span class="arrow">→</span>
      <span class="surr">${escapeHtml(e.surrogate)}</span>`;
    stats[e.type]=(stats[e.type]||0)+1; total++;
  }
  log.appendChild(div); trim(); renderChips();
  if(auto.checked) window.scrollTo(0,document.body.scrollHeight);
}
function escapeHtml(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
fetch('ui/stats').then(r=>r.json()).then(s=>{
  document.getElementById('ctx').textContent=s.context;
  if(s.show_originals){document.getElementById('maskmode').textContent='shown (real values)';
    document.getElementById('banner').className='banner';
    document.getElementById('banner').textContent='⚠ UI_SHOW_ORIGINALS is on — this page shows real values over HTTP.';}
  if(s.verbose){document.getElementById('verbose').textContent=' · verbose: catches re-shown every request';}
  (s.recent||[]).forEach(add);
  startStream(s.last_id||0);
}).catch(()=>startStream(0));
function startStream(after){
  const es=new EventSource('ui/events?after='+after);
  es.onopen=()=>dot.classList.add('live');
  es.onerror=()=>dot.classList.remove('live');
  es.onmessage=ev=>{try{add(JSON.parse(ev.data));}catch(e){}};
}
</script>
</body>
</html>
"""
