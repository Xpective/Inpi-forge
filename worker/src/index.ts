import nacl from "tweetnacl";
import bs58 from "bs58";

type Env = {
  KV_FORGE: KVNamespace;
  PUBLIC_RPC_URL: string;
  INPI_MINT: string;
  USDC_MINT: string;
  CREATOR_PUBKEY: string;
  TREASURY_WALLET: string;
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

// ---------- Helpers ----------
const ok = (data: any, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const bad = (msg: string, status = 400) =>
  ok({ error: msg }, status);

function now() { return Date.now(); }
function dayKey(ts = now()) {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${(d.getUTCMonth()+1).toString().padStart(2,"0")}-${d.getUTCDate().toString().padStart(2,"0")}`;
}
function weekKey(ts = now()) {
  const d = new Date(ts);
  const onejan = new Date(d.getUTCFullYear(),0,1);
  const week = Math.ceil((((d.getTime()-onejan.getTime())/86400000)+onejan.getUTCDay()+1)/7);
  return `${d.getUTCFullYear()}-W${week}`;
}
function randHex(len=32){ const a=new Uint8Array(len); crypto.getRandomValues(a); return [...a].map(x=>x.toString(16).padStart(2,"0")).join(""); }
const toBps = (x:number)=> Math.max(0, Math.min(10000, Math.floor(x)));

async function getKVBool(env:Env, k:string, def=false){
  const v = await env.KV_FORGE.get(`cfg:${k}`);
  if (v===null) return def;
  return v==="true" || v==="1";
}
async function getKVNum(env:Env, k:string, def=0){
  const v = await env.KV_FORGE.get(`cfg:${k}`);
  if (v===null) return def;
  return Number(v);
}
async function getKVStr(env:Env, k:string, def=""){
  const v = await env.KV_FORGE.get(`cfg:${k}`);
  return v ?? def;
}

// Default-Konfig einmalig setzen (nur wenn fehlt)
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
    "presale_price_inpi":"100",    // Beispiel: 100 INPI
    "presale_price_usdc":"5",      // Beispiel: 5 USDC
    "public_price_usdc":"7",
    "public_price_inpi_discount_bps":"1000" // 10%
  };
  for(const [k,v] of Object.entries(defaults)){
    const exists = await env.KV_FORGE.get(`cfg:${k}`);
    if(exists===null) await env.KV_FORGE.put(`cfg:${k}`, v);
  }
}

// ---------- Auth (SIWS) ----------
async function routeSiwsStart(env:Env){
  const nonce = randHex(16);
  const message = `Sign in to Inpinity Forge\nnonce=${nonce}\nts=${now()}`;
  // Session-Draft speichern (noch ohne pubkey)
  const sessionId = randHex(16);
  await env.KV_FORGE.put(`session:${sessionId}`, JSON.stringify({ nonce, createdAt: now() }), { expirationTtl: 3600 });
  return ok({ sessionId, message });
}
async function routeSiwsVerify(req:Request, env:Env){
  const { sessionId, pubkey, signature, message } = await req.json();
  if(!sessionId || !pubkey || !signature || !message) return bad("missing fields");
  const sessRaw = await env.KV_FORGE.get(`session:${sessionId}`);
  if(!sessRaw) return bad("session not found", 401);
  // Verify signature
  const pub = bs58.decode(pubkey);
  const sig = bs58.decode(signature);
  const okSig = nacl.sign.detached.verify(new TextEncoder().encode(message), sig, pub);
  if(!okSig) return bad("invalid signature", 401);
  // Bind wallet to session
  const sess = JSON.parse(sessRaw);
  sess.pubkey = pubkey;
  sess.verifiedAt = now();
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

// ---------- Gate (Pi-NFT Besitz prüfen) ----------
// P1-Stub: wir vertrauen auf Frontend-Check später; hier nur Flag
async function routeGate(env:Env, sess:any){
  // TODO: P2 – echten Besitz via RPC/Indexer prüfen
  return ok({ hasPass: true, piOrigin: { row: 7, digit_pi: 3, digit_phi: 1, rarity_score: 9, tier: "Legendary", is_axis: true } });
}

// ---------- Commit / Quote / Tx / Reveal ----------
type Commit = {
  id: string;
  pubkey: string;
  classId: string;
  currency: "INPI"|"USDC";
  options?: any;
  commitHash: string;
  serverNonce: string; // wird bei Reveal veröffentlicht
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

  // Rate-Limit pro Wallet
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
                              : /** Public INPI: Preis via Discount – P1 als Info im Frontend berechnen */
                                Number(await getKVNum(env,"public_price_usdc",7)); 
  }

  const serverNonce = randHex(32);
  const commitHash = await sha256hex(serverNonce);
  const commitId = randHex(16);

  const reference = await randomReferencePubkey(); // base58 Pubkey

  const payload: Commit = {
    id: commitId,
    pubkey: sess.pubkey,
    classId, currency, options,
    commitHash, serverNonce,
    createdAt: now(),
    price,
    presaleDaysLeft,
    reference
  };
  await env.KV_FORGE.put(`commit:${commitId}`, JSON.stringify(payload), { expirationTtl: 3600 });

  // noch keinen Count erhöhen – erst bei Reveal.
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
  // Slots: +2 wenn INPI gezahlt wird
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

  // Solana Pay URL (Wallet baut Tx, wir verifizieren via reference)
  // Format: solana:<recipient>?amount=..&spl-token=..&reference=..&label=..&message=..
  const recipient = env.TREASURY_WALLET;
  const label = encodeURIComponent("Inpinity Forge");
  const message = encodeURIComponent(`Forge ${c.classId} with ${c.currency}`);
  const url = `solana:${recipient}?amount=${amount}&spl-token=${mint}&reference=${c.reference}&label=${label}&message=${message}`;

  return ok({ solanaPayUrl: url, reference: c.reference, amount, currency: c.currency });
}

// P1: vereinfachtes Reveal – prüft nur, dass wir "irgendeine" Zahlung mit reference gesehen hätten.
// In P2 baust du hier echte RPC-Validierung (getSignaturesForAddress(reference) → prüfen, ob Transfer an TREASURY mit korrektem mint & amount).
async function routeReveal(req:Request, env:Env, sess:any){
  const { commitId } = await req.json();
  if(!commitId) return bad("missing commitId");
  const raw = await env.KV_FORGE.get(`commit:${commitId}`);
  if(!raw) return bad("commit not found", 404);
  const c: Commit = JSON.parse(raw);
  if(c.pubkey !== sess.pubkey) return bad("not your commit", 403);

  // TODO P2: echte Zahlung verifizieren (RPC). Hier P1-Stub:
  const paid = true;
  if(!paid) return bad("payment not found", 402);

  // ---- Seed/Rarity berechnen (mit Caps & Pi-Mods) ----
  // Pi-Origin P1-Stub (später aus /gate echte Werte nehmen):
  const pi = { row: 7, rarity_score: 9, digit_pi: 3, digit_phi: 1, is_axis: true };

  const seedInput = `${sess.pubkey}|${c.serverNonce}|${c.classId}|${now()}`;
  const ue_seed = await sha256hex(seedInput);

  // Baseline Gewichte in BPS
  let wCommon = 6000, wRare = 2500, wEpic = 1200, wLegend = 300;

  // Pi-Mods
  if (pi.row <= 8){ wLegend = Math.floor(wLegend * 1.5); wEpic = Math.floor(wEpic * 1.25); }
  else if (pi.row <= 32){ wEpic = Math.floor(wEpic * 1.10); }
  else { wCommon = Math.max(5500, wCommon); } // Common floor ≥55%

  // Legend hard cap in BPS
  const legendCapBps = await getKVNum(env,"legend_prob_cap_bps",800);
  wLegend = Math.min(wLegend, legendCapBps);

  // Normalize
  let total = wCommon + wRare + wEpic + wLegend;
  const r = await randBpsFromSeed(ue_seed);
  let outcome = "Common"; let acc = wCommon;
  if (r > acc){ acc += wRare; outcome = (r <= acc) ? "Rare" : outcome; }
  if (r > acc){ acc += wEpic; outcome = (r <= acc) ? "Epic" : outcome; }
  if (r > acc){ outcome = "Legendary"; }

  // Caps global (daily/weekly) – nur wenn Legendary
  if (outcome==="Legendary"){
    const dkey = `legend:day:${dayKey()}`;
    const wkey = `legend:week:${weekKey()}`;
    const daily = Number(await env.KV_FORGE.get(dkey) || "0");
    const weekly = Number(await env.KV_FORGE.get(wkey) || "0");
    const dCap = await getKVNum(env,"legend_cap_daily",34);
    const wCap = await getKVNum(env,"legend_cap_weekly",144);
    if (daily >= dCap || weekly >= wCap){
      outcome = "Epic"; // fallback downshift
    } else {
      await env.KV_FORGE.put(dkey, String(daily+1), { expirationTtl: 172800 });
      await env.KV_FORGE.put(wkey, String(weekly+1), { expirationTtl: 1209600 });
    }
  }

  // Slots (+2 bei INPI)
  const baseSlots = 2;
  let slots = c.currency==="INPI" ? baseSlots+2 : baseSlots;
  if (pi.rarity_score >= 8) slots += 1;

  // Stats (einfacher Start)
  const stats = baseStats(outcome, ue_seed, pi);

  // Wallet Day-Count erhöhen
  const day = dayKey();
  const wcountKey = `count:${sess.pubkey}:${day}`;
  const cur = Number(await env.KV_FORGE.get(wcountKey) || "0");
  await env.KV_FORGE.put(wcountKey, String(cur+1), { expirationTtl: 172800 });

  // Mint-Ticket speichern (Offline-Minter nimmt das auf)
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
    // metadataDraft ohne image URI (Pinning macht Offline-Minter)
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
        provenance: { commit: c.commitHash, reveal: c.serverNonce, payer_sig: "TBD" }
      }
    }
  };
  await env.KV_FORGE.put(`ticket:${mintTicketId}`, JSON.stringify(ticket), { expirationTtl: 1209600 });

  // Commit kann gelöscht werden; wir geben Reveal & Result zurück
  return ok({
    result: { rarity: outcome, slots, ue_seed },
    mintTicketId
  });
}

async function routeMints(env:Env, sess:any, url:URL){
  const owner = url.searchParams.get("owner") || sess.pubkey;
  // KV hat kein Query – P1: wir speichern unter index:owner
  const idx = await env.KV_FORGE.get(`idx:tickets:${owner}`);
  const ids: string[] = idx ? JSON.parse(idx) : [];
  const items = [];
  for(const id of ids){
    const raw = await env.KV_FORGE.get(`ticket:${id}`);
    if(raw) items.push(JSON.parse(raw));
  }
  return ok({ items });
}

// Helper: SHA-256 hex
async function sha256hex(s:string){
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  const a = new Uint8Array(d);
  return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function randBpsFromSeed(seed:string){
  // nehmen wir die ersten 4 Bytes → 0..65535 → skalieren auf 1..10000
  const n = parseInt(seed.slice(0,8),16) & 0xFFFF;
  return (n % 10000) + 1;
}
function baseStats(rarity:string, seed:string, pi:any){
  // sehr einfacher Start; später Balancing verfeinern
  const pick = (h:string, off:number, mod:number)=> ((parseInt(h.slice(off,off+4),16)%mod)+1);
  let attack = 10 + pick(seed,8,30);
  let defense= 10 + pick(seed,12,30);
  let speed  = 2 + pick(seed,16,9);
  let crit   = 2 + pick(seed,20,9);

  if (pi.row<=8){ (Math.random()>0.5 ? attack : defense)=Math.floor((Math.random()>0.5?attack:defense)*1.1); }
  if (pi.is_axis){ if (Math.random()>0.5) attack+=3; else defense+=3; }
  if (pi.digit_pi===pi.digit_phi){ crit+=2; speed+=2; }

  const elements = ["fire","lightning"]; // P1 fix; später ab UI
  return { attack, defense, speed, crit, res_fire: pick(seed,24,20), res_ice: pick(seed,28,20), elements };
}
async function randomReferencePubkey(){
  // Fake: generiere 32B und bs58 – in echter Welt: Keypair.pubkey
  const a=new Uint8Array(32); crypto.getRandomValues(a);
  return bs58.encode(a);
}

// ---------- Router ----------
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

    // Auth required
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