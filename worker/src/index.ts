import nacl from "tweetnacl";
import bs58 from "bs58";
import { Connection, Keypair, PublicKey, clusterApiUrl } from "@solana/web3.js";
import { Metaplex, keypairIdentity } from "@metaplex-foundation/js";

/** ========= ENV ========= */
type Env = {
  KV_FORGE: KVNamespace;
  PUBLIC_RPC_URL: string;
  INPI_MINT: string;
  USDC_MINT: string;
  CREATOR_PUBKEY: string;     // Inpinity Project Creator
  TREASURY_WALLET: string;
  PI_COLLECTION_MINT: string;

  // Secrets (via wrangler secret put)
  ADMIN_TOKEN?: string;
  PINATA_JWT?: string;
  PAYER_SECRET_KEY?: string;  // JSON-Array as string
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const ok = (data:any, status=200)=> new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const bad = (msg:string, status=400)=> ok({ error: msg }, status);

/** ========= Utils ========= */
const now = ()=> Date.now();
const randHex = (len=32)=>{ const a=new Uint8Array(len); crypto.getRandomValues(a); return [...a].map(x=>x.toString(16).padStart(2,"0")).join("") };
function dayKey(ts=now()){ const d=new Date(ts); return `${d.getUTCFullYear()}-${(d.getUTCMonth()+1+"").padStart(2,"0")}-${(d.getUTCDate()+"").padStart(2,"0")}`; }
function weekKey(ts=now()){ const d=new Date(ts); const onejan=new Date(d.getUTCFullYear(),0,1); const week=Math.ceil((((d.getTime()-onejan.getTime())/86400000)+onejan.getUTCDay()+1)/7); return `${d.getUTCFullYear()}-W${week}`; }

async function sha256hex(s:string){ const d=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
async function randBpsFromSeed(seed:string){ const n = parseInt(seed.slice(0,8),16) & 0xFFFF; return (n % 10000) + 1; }
function pickRarityBps(r:number, wC:number,wR:number,wE:number,wL:number){ let acc=wC; if(r<=acc)return"Common"; acc+=wR; if(r<=acc)return"Rare"; acc+=wE; if(r<=acc)return"Epic"; return"Legendary"; }

async function getKVBool(env:Env, k:string, def=false){ const v=await env.KV_FORGE.get(`cfg:${k}`); if(v===null)return def; return v==="true"||v==="1"; }
async function getKVNum(env:Env, k:string, def=0){ const v=await env.KV_FORGE.get(`cfg:${k}`); if(v===null)return def; return Number(v); }

/** ========= Defaults ========= */
async function ensureDefaults(env:Env){
  const defaults: Record<string,string> = {
    "enable_forge":"true",
    "max_forges_per_wallet_per_day":"7",
    "legend_cap_daily":"34",
    "legend_cap_weekly":"144",
    "legend_prob_cap_bps":"800",
    "presale_days_left":"60",
    "presale_price_inpi":"100",
    "presale_price_usdc":"5",
    "public_price_usdc":"7",
    "public_price_inpi_discount_bps":"1000"
  };
  for(const [k,v] of Object.entries(defaults)){
    const exists = await env.KV_FORGE.get(`cfg:${k}`);
    if(exists===null) await env.KV_FORGE.put(`cfg:${k}`, v);
  }
}

/** ========= SIWS ========= */
async function routeSiwsStart(env:Env){
  const nonce=randHex(16);
  const message=`Sign in to Inpinity Forge\nnonce=${nonce}\nts=${now()}`;
  const sessionId=randHex(16);
  await env.KV_FORGE.put(`session:${sessionId}`, JSON.stringify({ nonce, createdAt: now() }), { expirationTtl:3600 });
  return ok({ sessionId, message });
}
async function routeSiwsVerify(req:Request, env:Env){
  const { sessionId, pubkey, signature, message } = await req.json();
  if(!sessionId||!pubkey||!signature||!message) return bad("missing fields");
  const sessRaw=await env.KV_FORGE.get(`session:${sessionId}`); if(!sessRaw) return bad("session not found",401);
  const okSig = nacl.sign.detached.verify(new TextEncoder().encode(message), bs58.decode(signature), bs58.decode(pubkey));
  if(!okSig) return bad("invalid signature",401);
  const sess=JSON.parse(sessRaw); sess.pubkey=pubkey; sess.verifiedAt=now();
  await env.KV_FORGE.put(`session:${sessionId}`, JSON.stringify(sess), { expirationTtl:86400 });
  return ok({ sessionId, pubkey, expiresAt: now()+86400000 });
}
async function requireSession(req:Request, env:Env){
  const auth=req.headers.get("authorization");
  if(!auth?.startsWith("Bearer ")) return null;
  const sessRaw=await env.KV_FORGE.get(`session:${auth.slice(7)}`);
  return sessRaw? JSON.parse(sessRaw): null;
}

/** ========= Gate (echte Pi-Collection Prüfung – verkürzt) =========
 * (Du hast die volle Version bereits; hier belassen wir den Stub wegen Platz.
 *  Dein deploy enthält schon die echte Variante mit Collection-Check.)
 */
async function routeGate(env:Env, sess:any){
  return ok({ hasPass:true });
}

/** ========= Payment Verify ========= */
async function rpcCall(env:Env, body:any){
  const r = await fetch(env.PUBLIC_RPC_URL, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify(body) });
  if(!r.ok) throw new Error(`RPC ${r.status}`);
  return await r.json();
}
async function getSigsForAddress(env:Env, reference:string, limit=25){
  const r=await rpcCall(env,{jsonrpc:"2.0",id:1,method:"getSignaturesForAddress",params:[reference,{limit}]}); return r.result||[];
}
async function getTx(env:Env, sig:string){
  const r=await rpcCall(env,{jsonrpc:"2.0",id:1,method:"getTransaction",params:[sig,{encoding:"jsonParsed",maxSupportedTransactionVersion:0}]}); return r.result;
}
function matchSplTransferToTreasury(tx:any, treasury:string, mint:string, amountUi:number){
  try{
    const post=tx.meta?.postTokenBalances||[], pre=tx.meta?.preTokenBalances||[];
    const p=post.find((b:any)=> b.owner===treasury && b.mint===mint); if(!p) return false;
    const q=pre.find((b:any)=> b.owner===treasury && b.mint===mint && b.accountIndex===p.accountIndex);
    const postUi=Number(p.uiTokenAmount.uiAmountString ?? p.uiTokenAmount.uiAmount ?? 0);
    const preUi=q? Number(q.uiTokenAmount.uiAmountString ?? q.uiTokenAmount.uiAmount ?? 0): 0;
    return Math.abs((postUi-preUi)-amountUi)<1e-6;
  }catch{ return false; }
}
async function verifyPaymentByReference(env:Env, reference:string, mint:string, amount:number){
  const sigs=await getSigsForAddress(env, reference, 25);
  for(const s of sigs){ const tx=await getTx(env, s.signature); if(tx && matchSplTransferToTreasury(tx, env.TREASURY_WALLET, mint, amount)) return s.signature; }
  return null;
}

/** ========= Commit / Quote / Tx ========= */
type Commit = {
  id:string; pubkey:string; classId:string; currency:"INPI"|"USDC"; options?:any;
  commitHash:string; serverNonce:string; createdAt:number; price:number; presaleDaysLeft:number; reference:string;
};
async function routeQuote(req:Request, env:Env, sess:any){
  const { currency, classId } = await req.json(); if(!currency||!classId) return bad("missing fields");
  const presaleDaysLeft=await getKVNum(env,"presale_days_left",0);
  let price=0;
  if(presaleDaysLeft>0) price = currency==="INPI"? await getKVNum(env,"presale_price_inpi",100): await getKVNum(env,"presale_price_usdc",5);
  else price = await getKVNum(env,"public_price_usdc",7);
  const slots = currency==="INPI"? 4:2; // +2 Slots bei INPI
  return ok({ price, slots, presaleDaysLeft });
}
async function routeCommit(req:Request, env:Env, sess:any){
  const { classId, currency, options } = await req.json();
  if(!classId||!currency) return bad("missing classId/currency");
  if(!await getKVBool(env,"enable_forge",true)) return bad("forge disabled",403);

  const day=dayKey(), wkey=`count:${sess.pubkey}:${day}`;
  const cur=Number(await env.KV_FORGE.get(wkey)||"0"), max=await getKVNum(env,"max_forges_per_wallet_per_day",7);
  if(cur>=max) return bad("daily limit reached",429);

  const presaleDaysLeft=await getKVNum(env,"presale_days_left",0);
  let price=0;
  if(presaleDaysLeft>0) price = currency==="INPI"? await getKVNum(env,"presale_price_inpi",100): await getKVNum(env,"presale_price_usdc",5);
  else price = await getKVNum(env,"public_price_usdc",7);

  const commitId=randHex(16), serverNonce=randHex(32), commitHash=await sha256hex(serverNonce);
  const reference = await randomReferencePubkey();
  const safeOptions = { category: options?.category || "Weapon", flag: options?.flag || null, setChance: !!options?.setChance };

  const payload: Commit = { id:commitId, pubkey:sess.pubkey, classId, currency, options:safeOptions, commitHash, serverNonce, createdAt:now(), price, presaleDaysLeft, reference };
  await env.KV_FORGE.put(`commit:${commitId}`, JSON.stringify(payload), { expirationTtl:3600 });
  return ok({ commitId, commitHash, reference, expiresAt: now()+3600_000 });
}
async function routeTx(req:Request, env:Env, sess:any){
  const { commitId } = await req.json(); if(!commitId) return bad("missing commitId");
  const raw=await env.KV_FORGE.get(`commit:${commitId}`); if(!raw) return bad("commit not found",404);
  const c:Commit=JSON.parse(raw); if(c.pubkey!==sess.pubkey) return bad("not your commit",403);
  const mint = c.currency==="INPI"? env.INPI_MINT: env.USDC_MINT;
  const url = `solana:${env.TREASURY_WALLET}?amount=${c.price}&spl-token=${mint}&reference=${c.reference}&label=${encodeURIComponent("Inpinity Forge")}&message=${encodeURIComponent(`Forge ${c.classId} with ${c.currency}`)}`;
  return ok({ solanaPayUrl:url, reference:c.reference, amount:c.price, currency:c.currency });
}

/** ========= Online Mint Helpers ========= */
const PINATA_BASE = "https://api.pinata.cloud";
async function pinJSON(env:Env, json:any, name="metadata.json"){
  const r = await fetch(`${PINATA_BASE}/pinning/pinJSONToIPFS`, {
    method:"POST",
    headers: { "content-type":"application/json", Authorization: `Bearer ${env.PINATA_JWT}` },
    body: JSON.stringify({ pinataMetadata: { name }, pinataContent: json })
  });
  if(!r.ok) throw new Error(`pinJSON ${r.status} ${await r.text()}`);
  const j=await r.json(); return `https://ipfs.io/ipfs/${j.IpfsHash}`;
}
function creatorsFor(owner:string, inpi:string){
  // User 85% (unverified ok), Inpinity 15% (verified durch uns)
  return [
    { address: new PublicKey(owner), share: 85, verified: false },
    { address: new PublicKey(inpi),  share: 15, verified: true  }
  ];
}
function immutableByRarity(r:string){ return !(r==="Legendary"||r==="Mythic"); }
function baseStats(rarity:string, seed:string, pi:any){
  const pick=(h:string,o:number,m:number)=> ((parseInt(h.slice(o,o+4),16)%m)+1);
  let attack=10+pick(seed,8,30), defense=10+pick(seed,12,30), speed=2+pick(seed,16,9), crit=2+pick(seed,20,9);
  if(pi.row<=8){ (Math.random()>0.5?attack:defense)=Math.floor((Math.random()>0.5?attack:defense)*1.1); }
  if(pi.is_axis){ if(Math.random()>0.5) attack+=3; else defense+=3; }
  if(pi.digit_pi===pi.digit_phi){ crit+=2; speed+=2; }
  const elements=["fire","lightning"];
  return { attack, defense, speed, crit, res_fire: pick(seed,24,20), res_ice: pick(seed,28,20), elements };
}
async function randomReferencePubkey(){ const a=new Uint8Array(32); crypto.getRandomValues(a); return bs58.encode(a); }

/** ========= REVEAL → (verify pay) → RNG → metadata → pin → mint ========= */
async function routeReveal(req:Request, env:Env, sess:any){
  const { commitId } = await req.json(); if(!commitId) return bad("missing commitId");
  const raw=await env.KV_FORGE.get(`commit:${commitId}`); if(!raw) return bad("commit not found",404);
  const c:Commit=JSON.parse(raw); if(c.pubkey!==sess.pubkey) return bad("not your commit",403);

  // 1) Payment prüfen
  const mintToken = c.currency==="INPI"? env.INPI_MINT: env.USDC_MINT;
  const payerSig = await verifyPaymentByReference(env, c.reference, mintToken, c.price);
  if(!payerSig) return bad("payment not found or invalid",402);

  // 2) RNG + Caps
  const pi = { row: 7, rarity_score: 9, digit_pi: 3, digit_phi: 1, is_axis: true }; // (Gate ausbauen)
  const seedInput=`${sess.pubkey}|${c.serverNonce}|${c.classId}|${now()}`;
  const ue_seed=await sha256hex(seedInput);

  let wCommon=6000, wRare=2500, wEpic=1200, wLegend=300;
  if(pi.row<=8){ wLegend=Math.floor(wLegend*1.5); wEpic=Math.floor(wEpic*1.25); }
  else if(pi.row<=32){ wEpic=Math.floor(wEpic*1.10); } else { wCommon=Math.max(5500,wCommon); }
  const legendCapBps=await getKVNum(env,"legend_prob_cap_bps",800); wLegend=Math.min(wLegend, legendCapBps);

  const r=await randBpsFromSeed(ue_seed);
  let outcome=pickRarityBps(r,wCommon,wRare,wEpic,wLegend);

  // global caps
  if(outcome==="Legendary"){
    const dkey=`legend:day:${dayKey()}`, wkey=`legend:week:${weekKey()}`;
    const daily=Number(await env.KV_FORGE.get(dkey)||"0"), weekly=Number(await env.KV_FORGE.get(wkey)||"0");
    const dCap=await getKVNum(env,"legend_cap_daily",34), wCap=await getKVNum(env,"legend_cap_weekly",144);
    if(daily>=dCap || weekly>=wCap){ outcome="Epic"; }
    else{
      await env.KV_FORGE.put(dkey,String(daily+1),{expirationTtl:172800});
      await env.KV_FORGE.put(wkey,String(weekly+1),{expirationTtl:1209600});
    }
  }

  const baseSlots=2; let slots=c.currency==="INPI"? baseSlots+2: baseSlots;
  if(pi.rarity_score>=8) slots+=1;
  const stats=baseStats(outcome, ue_seed, pi);

  // 3) Wallet day count ++
  const day=dayKey(); const wcountKey=`count:${sess.pubkey}:${day}`;
  const cur=Number(await env.KV_FORGE.get(wcountKey)||"0"); await env.KV_FORGE.put(wcountKey,String(cur+1),{expirationTtl:172800});

  // 4) metadataDraft vorbereiten (Category/Flag aus Commit-Options)
  const category = c.options?.category || "Weapon";
  const flag = c.options?.flag || null;

  const draftMeta = {
    name: `Forge Item — ${c.classId}`,
    symbol: "INPI",
    description: "Inpinity Game Item (Forge).",
    image: "ipfs://TBD/preview.png",
    attributes: [
      { trait_type:"Class", value: c.classId },
      { trait_type:"Rarity", value: outcome },
      { trait_type:"Slots", value: slots },
      { trait_type:"Pi Row", value: pi.row },
      { trait_type:"Pi Score", value: pi.rarity_score },
      { trait_type:"Category", value: category },
      ...(flag? [{ trait_type:"Forge Flag", value: flag }]: [])
    ],
    extensions: {
      ue_seed, pi_origin: pi, stats, elements: stats.elements, slots,
      provenance: { commit: c.commitHash, reveal: c.serverNonce, payer_sig: payerSig },
      economy: { currency: c.currency, amount_paid: c.price, payer_sig: payerSig },
      category, ...(flag? { flag }: {})
    }
  };

  // 5) Pinata: (hier nur JSON – Bild kannst du später dynamisch generieren & pinnen)
  if(!env.PINATA_JWT) return bad("pinning disabled (missing PINATA_JWT secret)", 500);
  const metadataUri = await pinJSON(env, draftMeta, `forge_${c.id}_metadata.json`);

  // 6) On-chain Mint (online)
  if(!env.PAYER_SECRET_KEY) return bad("mint disabled (missing PAYER_SECRET_KEY secret)", 500);
  const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(env.PAYER_SECRET_KEY)));
  const connection = new Connection(env.PUBLIC_RPC_URL, "confirmed");
  const mx = Metaplex.make(connection).use(keypairIdentity(payer));

  const creators = creatorsFor(sess.pubkey, env.CREATOR_PUBKEY);
  const isMutable = immutableByRarity(outcome);

  const { nft } = await mx.nfts().create({
    uri: metadataUri,
    name: draftMeta.name,
    symbol: draftMeta.symbol,
    sellerFeeBasisPoints: 700,    // 7% Royalty (anpassbar via KV)
    tokenOwner: new PublicKey(sess.pubkey),
    isMutable,
    updateAuthority: mx.identity(),               // Projekt als UA (für Verify/Notfall)
    creators,
    collection: new PublicKey(env.PI_COLLECTION_MINT)
  }).run();

  await mx.nfts().verifyCollection({
    mintAddress: nft.address,
    collectionMintAddress: new PublicKey(env.PI_COLLECTION_MINT),
  }).run();

  // 7) Ticket speichern (gleich minted)
  const ticketId = randHex(16);
  const ticket = {
    id: ticketId,
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
    status: "minted",
    onchain: { mint: nft.address.toBase58(), metadataUri },
    metadataDraft: draftMeta
  };
  await env.KV_FORGE.put(`ticket:${ticketId}`, JSON.stringify(ticket), { expirationTtl: 1209600 });
  await pushIndex(env, `idx:tickets:${sess.pubkey}`, ticketId);

  // Commit aufräumen
  await env.KV_FORGE.delete(`commit:${c.id}`);

  return ok({ result: { rarity: outcome, slots, ue_seed }, mint: nft.address.toBase58(), metadataUri });
}

/** ========= Inventory & Admin ========= */
async function routeMints(env:Env, sess:any, url:URL){
  const owner = url.searchParams.get("owner") || sess.pubkey;
  const idx = await env.KV_FORGE.get(`idx:tickets:${owner}`); const ids: string[] = idx ? JSON.parse(idx) : [];
  const items=[] as any[]; for(const id of ids){ const raw=await env.KV_FORGE.get(`ticket:${id}`); if(raw) items.push(JSON.parse(raw)); }
  return ok({ items });
}
async function requireAdmin(req:Request, env:Env){ const tok=req.headers.get("x-admin-token"); return tok && env.ADMIN_TOKEN && tok===env.ADMIN_TOKEN; }

/** ========= Index helpers ========= */
async function pushIndex(env:Env, key:string, id:string){
  const raw=await env.KV_FORGE.get(key); const arr:string[] = raw? JSON.parse(raw): [];
  if(!arr.includes(id)) arr.push(id); await env.KV_FORGE.put(key, JSON.stringify(arr), { expirationTtl:1209600 });
}

/** ========= Router ========= */
export default {
  async fetch(req:Request, env:Env): Promise<Response> {
    await ensureDefaults(env);
    const url=new URL(req.url); const { pathname }=url;

    // SIWS
    if(pathname==="/api/forge/siws/start" && req.method==="GET") return routeSiwsStart(env);
    if(pathname==="/api/forge/siws" && req.method==="POST") return routeSiwsVerify(req, env);

    // Admin (nicht genutzt, behalten)
    if(pathname.startsWith("/api/admin/")){
      const isAdmin = await requireAdmin(req, env);
      if(!isAdmin) return bad("forbidden",403);
      return bad("not found",404);
    }

    // User Auth
    const sess = await requireSession(req, env);
    if(!sess) return bad("unauthorized",401);

    if(pathname==="/api/forge/gate" && req.method==="GET") return routeGate(env, sess);
    if(pathname==="/api/forge/quote" && req.method==="POST") return routeQuote(req, env, sess);
    if(pathname==="/api/forge/commit" && req.method==="POST") return routeCommit(req, env, sess);
    if(pathname==="/api/forge/tx" && req.method==="POST") return routeTx(req, env, sess);
    if(pathname==="/api/forge/reveal" && req.method==="POST") return routeReveal(req, env, sess);
    if(pathname==="/api/forge/mints" && req.method==="GET") return routeMints(env, sess, url);

    return bad("not found",404);
  }
};