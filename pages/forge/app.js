const API = location.origin.replace(/\/$/, "")  // gleiche Domain (Pages→Worker via Route)
let sessionId = null
let pubkey = null
let commitId = null
let reference = null

const $ = (q)=>document.querySelector(q)
const connectBtn = $('#connectBtn')
const walletSpan = $('#wallet')
const gateCard = $('#gate')
const gateMsg = $('#gateMsg')
const forgeCard = $('#forge')
const quoteBtn = $('#quoteBtn')
const quoteDiv = $('#quote')
const commitBtn = $('#commitBtn')
const payDiv = $('#pay')
const revealBtn = $('#revealBtn')
const resultDiv = $('#result')
const invCard = $('#inventory')
const itemsUl = $('#items')

async function phantomAvailable(){
  return typeof window.solana !== 'undefined' && window.solana.isPhantom
}

async function siwsStart(){
  const r = await fetch(`${API}/api/forge/siws/start`)
  return r.json()
}
async function siwsVerify(message, signature, pubkey){
  const r = await fetch(`${API}/api/forge/siws`, {
    method:"POST", headers:{'content-type':'application/json'},
    body: JSON.stringify({ sessionId, pubkey, signature, message })
  })
  if(!r.ok) throw new Error('SIWS verify failed')
  return r.json()
}
function authHeaders(){
  return { 'authorization': `Bearer ${sessionId}`, 'content-type': 'application/json' }
}

connectBtn.onclick = async ()=>{
  try{
    if(!(await phantomAvailable())){ alert('Phantom nicht gefunden'); return; }
    const resp = await siwsStart()
    sessionId = resp.sessionId
    const provider = window.solana
    const { publicKey } = await provider.connect({ onlyIfTrusted:false })
    pubkey = publicKey.toString()
    walletSpan.textContent = pubkey.slice(0,4)+'…'+pubkey.slice(-4)

    const message = resp.message
    const encodedMessage = new TextEncoder().encode(message)
    const signed = await provider.signMessage(encodedMessage, 'utf8')
    const signature = signed.signature ? bs58encode(signed.signature) : bs58encode(signed)
    await siwsVerify(message, signature, pubkey)

    // Gate
    gateCard.classList.remove('hidden')
    const g = await fetch(`${API}/api/forge/gate`, { headers: authHeaders() }).then(r=>r.json())
    gateMsg.textContent = g.hasPass ? 'Pass OK – Forge freigeschaltet.' : 'Kein Pass gefunden.'
    if (g.hasPass) forgeCard.classList.remove('hidden')
    invCard.classList.remove('hidden')
    loadInventory()

  }catch(e){ console.error(e); alert(e.message||'Fehler beim Verbinden') }
}

quoteBtn.onclick = async ()=>{
  const classId = $('#classId').value
  const currency = document.querySelector('input[name="cur"]:checked').value
  const r = await fetch(`${API}/api/forge/quote`, {
    method:"POST", headers: authHeaders(),
    body: JSON.stringify({ classId, currency })
  }).then(r=>r.json())
  quoteDiv.textContent = `Preis: ${r.price} ${currency} — Slots: ${r.slots} (Presale: ${r.presaleDaysLeft} Tage)`
  commitBtn.disabled = false
}

commitBtn.onclick = async ()=>{
  const classId = $('#classId').value
  const currency = document.querySelector('input[name="cur"]:checked').value
  const r = await fetch(`${API}/api/forge/commit`, {
    method:"POST", headers: authHeaders(),
    body: JSON.stringify({ classId, currency })
  }).then(r=>r.json())
  commitId = r.commitId
  reference = r.reference
  payDiv.innerHTML = `
    <div>Commit OK. Öffne Solana-Pay Link:</div>
    <p><a href="${(await txURL())}" target="_blank">${(await txURL())}</a></p>
    <small>Nach Zahlung: „Reveal“ klicken.</small>
  `
  revealBtn.disabled = false
}

async function txURL(){
  const r = await fetch(`${API}/api/forge/tx`, {
    method:"POST", headers: authHeaders(),
    body: JSON.stringify({ commitId })
  }).then(r=>r.json())
  return r.solanaPayUrl
}

revealBtn.onclick = async ()=>{
  const r = await fetch(`${API}/api/forge/reveal`, {
    method:"POST", headers: authHeaders(),
    body: JSON.stringify({ commitId })
  }).then(r=>r.json())
  resultDiv.textContent = `Ergebnis: ${r.result.rarity} — Slots: ${r.result.slots}`
  loadInventory()
}

async function loadInventory(){
  itemsUl.innerHTML = ''
  const r = await fetch(`${API}/api/forge/mints`, { headers: authHeaders() }).then(r=>r.json())
  for(const it of r.items){
    const li = document.createElement('li')
    li.textContent = `${it.classId} — ${it.rarity} — Slots ${it.slots} — Ticket ${it.id}`
    itemsUl.appendChild(li)
  }
}

// --- bs58 minimal ---
function bs58encode(bytes){
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  const BASE = ALPHABET.length
  let i, j, digits = [0]
  for (i = 0; i < bytes.length; ++i) {
    for (j = 0; j < digits.length; ++j) digits[j] <<= 8
    digits[0] += bytes[i]
    let carry = 0
    for (j = 0; j < digits.length; ++j) {
      digits[j] += carry
      carry = (digits[j] / BASE) | 0
      digits[j] %= BASE
    }
    while (carry) { digits.push(carry % BASE); carry = (carry / BASE) | 0 }
  }
  for (i = 0; bytes[i] === 0 && i < bytes.length - 1; ++i) digits.push(0)
  return digits.reverse().map(d => ALPHABET[d]).join('')
}