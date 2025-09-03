import nacl from "tweetnacl";
import bs58 from "bs58";

/** ======== ENV ======== */
type Env = {
  KV_FORGE: KVNamespace;
  PUBLIC_RPC_URL: string;
  INPI_MINT: string;
  USDC_MINT: string;
  CREATOR_PUBKEY: string;
  TREASURY_WALLET: string;
  ADMIN_TOKEN?: string;
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const ok = (data: any, status = 200) => new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const bad = (msg: string, status = 400) => ok({ error: msg }, status);

const now = () => Date.now();
function dayKey(ts = now()) {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${(d.getUTCMonth()+1+"").padStart(2,"0")}-${(d.getUTCDate()+"").padStart(2,"0")}`;
}
function weekKey(ts = now()) {
  const d = new Date(ts);
  const onejan = new Date(d.getUTCFullYear(),0,1);
  const week = Math.ceil((((d.getTime()-onejan.getTime())/86400000)+onejan.getUTCDay()+1)/7);
  return `${d.getUTCFullYear()}-W${week}`;
}
function randHex(len=32){ const a=new Uint8Array(len); crypto.getRandomValues(a); return [...a].map(x=>x.toString(16).padStart(2,"0")).join(""); }

/** ======== KV GETTERS ======== */
async function getKVBool(env:Env, k:string, def=false){
  const v = await env.KV_FORGE.get(`cfg:${k}`); if (v===null) return def; return v==="true" || v==="1";
}
async function getKVNum(env:Env, k:string, def=0){
  const v = await env.KV_FORGE.get(`cfg:${k}`); if (v===null) return def; return Number(v);
}
async function getKVStr(env:Env, k:string, def=""){
  const v = await env.KV_FORGE.get(`cfg:${k}`); return v ?? def;
}

/** ======== DEFAULTS (einmalig) ======== */
async function ensureDefaults(env:Env){
  const defaults: Record<string,string> = {
    "enable_forge":"true",
    "enable_cnft":"false",
    "enable_inpi_discount":"true",
    "max_forges_per_wallet_per_day":"7",
    "legend_cap_daily":"34",
    "legend_cap_weekly":"144",
    "legend_prob_cap_bps":"800",
    "presale_days_left":"60",
    "presale_price_inpi":"100",    // Beispiel
    "presale_price_usdc":"5",      // Beispiel
    "public_price_usdc":"7",
    "public_price_inpi_discount_bps":"1000" // 10%
  };
  for(const [k,v] of Object.entries(defaults)){
    const exists = await env.KV_FORGE.get(`cfg:${k}`);
    if(exists===null) await env.KV_FORGE.put(`cfg:${k}`, v);
  }
}

/** ======== SIWS ======== */
async function routeSiwsStart(env:Env){
  const nonce = randHex(16);
  const message = `Sign in to Inpinity Forge\nnonce=${nonce}\nts=${now()}`;
  const sessionId = randHex(16);
  await env.KV_FORGE.put(`session:${sessionId}`, JSON.stringify({ nonce, createdAt: now() }), { expirationTtl: 3600 });
  return ok({ sessionId, message });
}
async function routeSiwsVerify(req:Request, env:Env){
  const { sessionId, pubkey, signature, message } = await req.json();
  if(!sessionId || !pubkey || !signature || !message) return bad("missing fields");
  const sessRaw = await env.KV_FORGE.get(`session:${sessionId}`);
  if(!sessRaw) return bad("session not found", 401);
  const pub = bs58.decode(pubkey);
  const sig = bs58.decode(signature);
  const okSig = nacl.sign.detached.verify(new TextEncoder().encode(message), sig, pub);
  if(!okSig) return bad("invalid signature", 401);
  const sess = JSON.parse(sessRaw);
  sess.pubkey = pubkey; sess.verifiedAt = now();
  await env.KV_FORGE.put(`session:${sessionId}`, JSON.stringify(sess), { expirationTtl: 86400 });
  return ok({ sessionId, pubkey, expiresAt: now()+86400000 });
}
async function requireSession(req:Request, env:Env){
  const auth = req.headers.get("authorization");
  if(!auth?.startsWith("Bearer ")) return null;
  const sessionId = auth.slice(7);
  const sessRaw = await env.KV_FORGE.get(`session:${sessionId}`);
  if(!sessRaw) return null;
  return JSON.parse(sessRaw);
}

/** ======== Gate (P2+: echter Check folgt) ======== */
async function routeGate(env:Env, sess:any){
  // TODO (P2+): Echten Pi-Pyramide NFT Besitz via RPC/Indexer verifizieren.
  return ok({ hasPass: true, piOrigin: { row:7, digit_pi:3, digit_phi:1, rarity_score:9, tier:"Legendary", is_axis:true } });
}

/** ======== Payment Verify (P2) ======== */
async function fetchJson(url: string, init?: RequestInit) {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`);
  return await r.json();
}
async function rpcCall(rpc:string, body:any){
  return fetchJson(rpc, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify(body) });
}
async function getSigsForAddress(rpc: string, reference: string, limit = 20) {
  const body = { jsonrpc:"2.0", id:1, method:"getSignaturesForAddress", params:[ reference, { limit } ] };
  const r = await rpcCall(rpc, body);
  return r.result as any[];
}
async function getTx(rpc:string, sig:string){
  const body = { jsonrpc:"2.0", id:1, method:"getTransaction", params:[ sig, { encoding:"jsonParsed", maxSupportedTransactionVersion:0 } ] };
  const r = await rpcCall(rpc, body);
  return r.result;
}
function matchSplTransferToTreasury(tx:any, treasury:string, mint:string, amountUi:number){
  try{
    const meta = tx.meta; const message = tx.transaction?.message;
    if(!meta || !message) return false;
    const post = meta.postTokenBalances || []; const pre = meta.preTokenBalances || [];
    const postForTreasury = post.find((b:any)=> b.owner===treasury && b.mint===mint);
    if(!postForTreasury) return false;
    const preForTreasury = pre.find((b:any)=> b.owner===treasury && b.mint===mint && b.accountIndex===postForTreasury.accountIndex);
    const postUi = Number(postForTreasury.uiTokenAmount.uiAmountString ?? postForTreasury.uiTokenAmount.uiAmount ?? 0);
    const preUi  = preForTreasury ? Number(preForTreasury.uiTokenAmount.uiAmountString ?? preForTreasury.uiTokenAmount.uiAmount ?? 0) : 0;
    const delta  = +(postUi - preUi).toFixed(9);
    return Math.abs(delta - amountUi) < 1e-6;
  }catch{ return false; }
}
async function verifyPaymentByReference(env:Env, reference:string, mint:string, amount:number){
  const rpc = env.PUBLIC_RPC_URL;
  const sigs = await getSigsForAddress(rpc, reference, 25);
  for(const s of sigs){
    const tx = await getTx(rpc, s.signature);
    if(!tx) continue;
    const ok = matchSplTransferToTreasury(tx, env.TREASURY_WALLET, mint, amount);
    if(ok) return s.signature;
  }
  return null;
}

/** ======== Commit / Quote / Tx / Reveal ======== */
type Commit = {
  id: string;
  pubkey: string;
  classId: string;
  currency: "INPI"|"USDC";
  options?: any;
  commitHash: string;
  serverNonce: string;
  createdAt: number;
  price: number;
  presaleDaysLeft: number;
  reference: string; // base58 pubkey
};

async function routeCommit(req:Request, env:Env, sess:any){
  const { classId, currency, options } = await req.json();
  if(!classId || !currency) return bad("missing classId/currency");
  const enable = await getKVBool(env,"enable_forge",true);
  if(!enable) return bad("forge disabled", 403);

  // per-wallet limit
  const day = dayKey();
  const wkey = `count:${sess.pubkey}:${day}`;
  const cur = Number(await env.KV_FORGE.get(wkey) || "0");
  const max = await getKVNum(env,"max_forges_per_wallet_per_day",7);
  if(cur >= max) return bad("daily limit reached", 429);

  // Preis
  const presaleDaysLeft = await getKVNum(env,"presale_days_left",0);
  let price = 0;
  if (presaleDaysLeft>0) {
    price = currency==="INPI" ? Number(await getKVNum(env,"presale_price_inpi",100))
                              : Number(await getKVNum(env,"presale_price_usdc",5));
  } else {
    price = currency==="USDC" ? Number(await getKVNum(env,"public_price_usdc",7))
                              : Number(await getKVNum(env,"public_price_usdc",7)); // INPI public: Frontend calc via oracle
  }

  const serverNonce = randHex(32);
  const commitHash = await sha256hex(serverNonce);
  const commitId = randHex(16);
  const reference = await randomReferencePubkey();

  const payload: Commit = {
    id: commitId, pubkey: sess.pubkey, classId, currency, options,
    commitHash, serverNonce, createdAt: now(), price, presaleDaysLeft, reference
  };
  await env.KV_FORGE.put(`commit:${commitId}`, JSON.stringify(payload), { expirationTtl: 3600 });
  return ok({ commitId, commitHash, reference, expiresAt: now()+3600_000 });
}

async function routeQuote(req:Request, env:Env, sess:any){
  const { currency, classId } = await req.json();
  if(!currency || !classId) return bad("missing fields");
  const presaleDaysLeft = await getKVNum(env,"presale_days_left",0);
  let price = 0;
  if (presaleDaysLeft>0) {
    price = currency==="INPI" ? Number(await getKVNum(env,"presale_price_inpi",100))
                              : Number(await getKVNum(env,"presale_price_usdc",5));
  } else {
    price = currency==="USDC" ? Number(await getKVNum(env,"public_price_usdc",7))
                              : Number(await getKVNum(env,"public_price_usdc",7));
  }
  const baseSlots = 2;
  const slots = currency==="INPI" ? baseSlots+2 : baseSlots;
  return ok({ price, slots, presaleDaysLeft });
}

async function routeTx(req:Request, env:Env, sess:any){
  const { commitId } = await req.json();
  if(!commitId) return bad("missing commitId");
  const raw = await env.KV_FORGE.get(`commit:${commitId}`);
  if(!raw) return bad("commit not found", 404);
  const c: Commit = JSON.parse(raw);
  if(c.pubkey !== sess.pubkey) return bad("not your commit", 403);

  const mint = c.currency==="INPI" ? env.INPI_MINT : env.USDC_MINT;
  const amount = c.price;
  const recipient = env.TREASURY_WALLET;
  const label = encodeURIComponent("Inpinity Forge");
  const message = encodeURIComponent(`Forge ${c.classId} with ${c.currency}`);

  // Solana Pay URL
  const url = `solana:${recipient}?amount=${amount}&spl-token=${mint}&reference=${c.reference}&label=${label}&message=${message}`;
  return ok({ solanaPayUrl: url, reference: c.reference, amount, currency: c.currency });
}

async function routeReveal(req:Request, env:Env, sess:any){
  const { commitId } = await req.json();
  if(!commitId) return bad("missing commitId");
  const raw = await env.KV_FORGE.get(`commit:${commitId}`);
  if(!raw) return bad("commit not found", 404);
  const c: Commit = JSON.parse(raw);
  if(c.pubkey !== sess.pubkey) return bad("not your commit", 403);

  // ====== P2: echte Zahlung prüfen ======
  const mint = c.currency==="INPI" ? env.INPI_MINT : env.USDC_MINT;
  const payerSig = await verifyPaymentByReference(env, c.reference, mint, c.price);
  if (!payerSig) return bad("payment not found or invalid", 402);

  // ====== RNG + Caps + Stats ======
  const pi = { row: 7, rarity_score: 9, digit_pi: 3, digit_phi: 1, is_axis: true }; // TODO: echte Werte via Gate

  const seedInput = `${sess.pubkey}|${c.serverNonce}|${c.classId}|${now()}`;
  const ue_seed = await sha256hex(seedInput);

  let wCommon = 6000, wRare = 2500, wEpic = 1200, wLegend = 300;
  if (pi.row <= 8){ wLegend = Math.floor(wLegend*1.5); wEpic = Math.floor(wEpic*1.25); }
  else if (pi.row <= 32){ wEpic = Math.floor(wEpic*1.10); }
  else { wCommon = Math.max(5500, wCommon); }

  const legendCapBps = await getKVNum(env,"legend_prob_cap_bps",800);
  wLegend = Math.min(wLegend, legendCapBps);

  const r = await randBpsFromSeed(ue_seed);
  let outcome = pickRarityBps(r, wCommon, wRare, wEpic, wLegend);

  // global caps
  if (outcome==="Legendary"){
    const dkey = `legend:day:${dayKey()}`;
    const wkey = `legend:week:${weekKey()}`;
    const daily = Number(await env.KV_FORGE.get(dkey) || "0");
    const weekly = Number(await env.KV_FORGE.get(wkey) || "0");
    const dCap = await getKVNum(env,"legend_cap_daily",34);
    const wCap = await getKVNum(env,"legend_cap_weekly",144);
    if (daily >= dCap || weekly >= wCap){
      outcome = "Epic";
    } else {
      await env.KV_FORGE.put(dkey, String(daily+1), { expirationTtl: 172800 });
      await env.KV_FORGE.put(wkey, String(weekly+1), { expirationTtl: 1209600 });
    }
  }

  const baseSlots = 2;
  let slots = c.currency==="INPI" ? baseSlots+2 : baseSlots;
  if (pi.rarity_score >= 8) slots += 1;

  const stats = baseStats(outcome, ue_seed, pi);

  // Wallet day count ++
  const day = dayKey();
  const wcountKey = `count:${sess.pubkey}:${day}`;
  const cur = Number(await env.KV_FORGE.get(wcountKey) || "0");
  await env.KV_FORGE.put(wcountKey, String(cur+1), { expirationTtl: 172800 });

  // Mint-Ticket speichern
  const mintTicketId = randHex(16);
  const ticket = {
    id: mintTicketId,
    owner: sess.pubkey,
    commitId: c.id,
    classId: c.classId,
    rarity: outcome,
    slots,
    ue_seed,
    currency: c.currency,
    amount_paid: c.price,
    reference: c.reference,
    createdAt: now(),
    pi_origin: pi,
    stats,
    status: "ready",
    metadataDraft: {
      name: `Forge Item — ${c.classId}`,
      symbol: "INPI",
      description: "Inpinity Game Item (Forge).",
      image: "ipfs://TBD/preview.png",
      attributes: [
        { trait_type:"Class", value: c.classId },
        { trait_type:"Rarity", value: outcome },
        { trait_type:"Slots", value: slots },
        { trait_type:"Pi Row", value: pi.row },
        { trait_type:"Pi Score", value: pi.rarity_score }
      ],
      extensions: {
        ue_seed,
        pi_origin: pi,
        stats,
        elements: stats.elements,
        slots,
        provenance: { commit: c.commitHash, reveal: c.serverNonce, payer_sig: payerSig }
      }
    }
  };
  await env.KV_FORGE.put(`ticket:${mintTicketId}`, JSON.stringify(ticket), { expirationTtl: 1209600 });

  // Index aktualisieren (owner + ready)
  await pushIndex(env, `idx:tickets:${sess.pubkey}`, mintTicketId);
  await pushIndex(env, `idx:tickets:ready`, mintTicketId);

  return ok({ result: { rarity: outcome, slots, ue_seed }, mintTicketId });
}

async function routeMints(env:Env, sess:any, url:URL){
  const owner = url.searchParams.get("owner") || sess.pubkey;
  const idx = await env.KV_FORGE.get(`idx:tickets:${owner}`);
  const ids: string[] = idx ? JSON.parse(idx) : [];
  const items = [];
  for(const id of ids){
    const raw = await env.KV_FORGE.get(`ticket:${id}`);
    if(raw) items.push(JSON.parse(raw));
  }
  return ok({ items });
}

/** ======== Admin ======== */
async function requireAdmin(req: Request, env: Env) {
  const tok = req.headers.get("x-admin-token");
  return tok && env.ADMIN_TOKEN && tok === env.ADMIN_TOKEN;
}
async function routeAdminTickets(env:Env, url:URL){
  const idxRaw = await env.KV_FORGE.get("idx:tickets:ready");
  const ids: string[] = idxRaw ? JSON.parse(idxRaw) : [];
  const out = [];
  for (const id of ids.slice(0, 50)) {
    const raw = await env.KV_FORGE.get(`ticket:${id}`);
    if (raw) out.push(JSON.parse(raw));
  }
  return ok({ items: out });
}
async function routeAdminMarkMinted(req:Request, env:Env){
  const { id, mintPubkey, metadataUri } = await req.json();
  if (!id || !mintPubkey || !metadataUri) return bad("missing fields");
  const raw = await env.KV_FORGE.get(`ticket:${id}`);
  if (!raw) return bad("ticket not found", 404);
  const t = JSON.parse(raw);
  t.status = "minted";
  t.onchain = { mint: mintPubkey, metadataUri };
  await env.KV_FORGE.put(`ticket:${id}`, JSON.stringify(t), { expirationTtl: 1209600 });

  // aus ready-index entfernen
  await removeFromIndex(env, "idx:tickets:ready", id);

  // optional: in owner-index bleibt Ticket enthalten (Historie)
  return ok({ ok: true });
}

/** ======== Utils ======== */
async function sha256hex(s:string){
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  const a = new Uint8Array(d);
  return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function randBpsFromSeed(seed:string){
  const n = parseInt(seed.slice(0,8),16) & 0xFFFF;
  return (n % 10000) + 1;
}
function pickRarityBps(r:number, wC:number,wR:number,wE:number,wL:number){
  let acc = wC; if (r <= acc) return "Common";
  acc += wR;    if (r <= acc) return "Rare";
  acc += wE;    if (r <= acc) return "Epic";
  return "Legendary";
}
function baseStats(rarity:string, seed:string, pi:any){
  const pick = (h:string, off:number, mod:number)=> ((parseInt(h.slice(off,off+4),16)%mod)+1);
  let attack = 10 + pick(seed,8,30);
  let defense= 10 + pick(seed,12,30);
  let speed  = 2 + pick(seed,16,9);
  let crit   = 2 + pick(seed,20,9);
  if (pi.row<=8){ (Math.random()>0.5 ? attack : defense) = Math.floor((Math.random()>0.5?attack:defense)*1.1); }
  if (pi.is_axis){ if (Math.random()>0.5) attack+=3; else defense+=3; }
  if (pi.digit_pi===pi.digit_phi){ crit+=2; speed+=2; }
  const elements = ["fire","lightning"]; // P1 fix; später dynamisch
  return { attack, defense, speed, crit, res_fire: pick(seed,24,20), res_ice: pick(seed,28,20), elements };
}
async function randomReferencePubkey(){
  const a=new Uint8Array(32); crypto.getRandomValues(a);
  return bs58.encode(a);
}
async function pushIndex(env:Env, key:string, id:string){
  const raw = await env.KV_FORGE.get(key);
  const arr: string[] = raw ? JSON.parse(raw) : [];
  if (!arr.includes(id)) arr.push(id);
  await env.KV_FORGE.put(key, JSON.stringify(arr), { expirationTtl: 1209600 });
}
async function removeFromIndex(env:Env, key:string, id:string){
  const raw = await env.KV_FORGE.get(key);
  if(!raw) return;
  let arr: string[] = JSON.parse(raw);
  arr = arr.filter(x => x !== id);
  await env.KV_FORGE.put(key, JSON.stringify(arr), { expirationTtl: 1209600 });
}

/** ======== Router ======== */
export default {
  async fetch(req:Request, env:Env): Promise<Response> {
    await ensureDefaults(env);
    const url = new URL(req.url);
    const { pathname } = url;

    // SIWS
    if (pathname==="/api/forge/siws/start" && req.method==="GET")
      return routeSiwsStart(env);
    if (pathname==="/api/forge/siws" && req.method==="POST")
      return routeSiwsVerify(req, env);

    // Admin
    if (pathname.startsWith("/api/admin/")) {
      const isAdmin = await requireAdmin(req, env);
      if (!isAdmin) return bad("forbidden", 403);
      if (pathname === "/api/admin/tickets" && req.method === "GET")
        return routeAdminTickets(env, url);
      if (pathname === "/api/admin/mark-minted" && req.method === "POST")
        return routeAdminMarkMinted(req, env);
      return bad("not found", 404);
    }

    // User Auth
    const sess = await requireSession(req, env);
    if(!sess) return bad("unauthorized", 401);

    if (pathname==="/api/forge/gate" && req.method==="GET")
      return routeGate(env, sess);
    if (pathname==="/api/forge/commit" && req.method==="POST")
      return routeCommit(req, env, sess);
    if (pathname==="/api/forge/quote" && req.method==="POST")
      return routeQuote(req, env, sess);
    if (pathname==="/api/forge/tx" && req.method==="POST")
      return routeTx(req, env, sess);
    if (pathname==="/api/forge/reveal" && req.method==="POST")
      return routeReveal(req, env, sess);
    if (pathname==="/api/forge/mints" && req.method==="GET")
      return routeMints(env, sess, url);

    return bad("not found", 404);
  }
};