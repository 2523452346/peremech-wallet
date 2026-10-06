// Анонимный ящик: всё, что делает браузер дарителя и получателя.
//
// Работает одинаково в браузере и в Node (проверки): шифрование — встроенный
// WebCrypto, хеш — Poseidon (poseidon-lite, совпадает со схемой), доказательство — snarkjs.
//
// Ключи получателя:
//   secret — тайное число; из него owner = Poseidon(secret), «замок» для конвертов,
//            и метки забора. Лежит только в файле ключа и в памяти открытой страницы.
//   view   — пара ключей P-256 для писем: открытая половина в профиле, закрытая
//            в файле ключа. Ею получатель находит и читает свои конверты.
//
// Конверт в блокчейне (событие Deposit): commitment = Poseidon(owner, blinding) и письмо:
//   [1 байт версии][65 байт одноразового ключа дарителя][1 байт подсказки][12 байт iv][шифровка]
// Внутри шифровки JSON {b: blinding, n: имя, t: текст}, дополненный до кратного 128.

import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";

export const LEVELS = 20;
export const MAX_INPUTS = 4;
export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ENVELOPE_VERSION = 1;
const HKDF_INFO = new TextEncoder().encode("peremech-anon-box-v1");
const PAD = 128;

const subtle = globalThis.crypto.subtle;
// Оставлено для совместимости: хешу подготовка больше не нужна.
export async function init() {}

export function hash(inputs) {
    const v = inputs.map(BigInt);
    return v.length === 1 ? poseidon1(v) : poseidon2(v);
}

// ---------------------------------------------------------------- числа и байты

export function randomField() {
    const b = new Uint8Array(31);
    globalThis.crypto.getRandomValues(b);
    return bytesToBig(b);
}

function bytesToBig(b) {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
}

export function toHex(b) {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(h) {
    h = h.replace(/^0x/, "");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
}

function b64(b) {
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s);
}

function unb64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// ---------------------------------------------------------------- ключи

// Новые ключи получателя. Результат — то, что ложится в файл ключа.
export async function newKeys() {
    const secret = randomField();
    const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const jwk = await subtle.exportKey("jwk", pair.privateKey);
    return { v: 1, secret: secret.toString(), view: jwk };
}

// Замок — открытая часть ключей: его показывает профиль получателя.
export async function lockOf(keys) {
    const pub = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: keys.view.x, y: keys.view.y }, { name: "ECDH", namedCurve: "P-256" }, true, []);
    const raw = new Uint8Array(await subtle.exportKey("raw", pub));
    return { v: 1, owner: ownerOf(keys).toString(), view: b64(raw) };
}

export function ownerOf(keys) {
    return hash([BigInt(keys.secret)]);
}

export function commitmentOf(owner, blinding) {
    return hash([BigInt(owner), BigInt(blinding)]);
}

export function nullifierOf(secret, commitment) {
    return hash([BigInt(secret), BigInt(commitment)]);
}

// ---------------------------------------------------------------- письма

async function sharedKey(privKey, pubRaw) {
    const pub = await subtle.importKey("raw", pubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await subtle.deriveBits({ name: "ECDH", public: pub }, privKey, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const bits = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO }, hk, 264));
    const aes = await subtle.importKey("raw", bits.slice(1), "AES-GCM", false, ["encrypt", "decrypt"]);
    return { tag: bits[0], aes };
}

function padded(json) {
    const body = new TextEncoder().encode(json);
    const size = Math.ceil((body.length + 1) / PAD) * PAD;
    const out = new Uint8Array(size).fill(0x20); // пробелы: JSON.parse их пропустит
    out.set(body);
    return out;
}

// Запечатать конверт замком получателя. Возвращает то, что уходит в ящик.
export async function seal(lock, message) {
    const blinding = randomField();
    const commitment = commitmentOf(lock.owner, blinding);

    const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ephRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
    const { tag, aes } = await sharedKey(eph.privateKey, unb64(lock.view));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const plain = padded(JSON.stringify({ b: blinding.toString(), n: String(message.name || ""), t: String(message.text || "") }));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aes, plain));

    const env = new Uint8Array(1 + 65 + 1 + 12 + ct.length);
    env[0] = ENVELOPE_VERSION;
    env.set(ephRaw, 1);
    env[66] = tag;
    env.set(iv, 67);
    env.set(ct, 79);
    return { commitment, envelope: env };
}

// Попробовать открыть конверт своим ключом. Чужой — null.
export async function open(keys, commitment, env) {
    if (!env || env.length < 80 || env[0] !== ENVELOPE_VERSION) return null;
    const priv = await viewPrivate(keys);
    let k;
    try {
        k = await sharedKey(priv, env.slice(1, 66));
    } catch {
        return null;
    }
    if (k.tag !== env[66]) return null; // подсказка не сошлась — точно не наш
    let plain;
    try {
        plain = await subtle.decrypt({ name: "AES-GCM", iv: env.slice(67, 79) }, k.aes, env.slice(79));
    } catch {
        return null;
    }
    const msg = JSON.parse(new TextDecoder().decode(plain));
    // Письмо могли приложить к чужому отпечатку — такой конверт не наш.
    if (commitmentOf(ownerOf(keys), msg.b) !== BigInt(commitment)) return null;
    return { blinding: BigInt(msg.b), name: msg.n, text: msg.t };
}

const privCache = new WeakMap();
async function viewPrivate(keys) {
    if (!privCache.has(keys)) {
        privCache.set(keys, await subtle.importKey("jwk", keys.view, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]));
    }
    return privCache.get(keys);
}

// ---------------------------------------------------------------- дерево

// Нулевой лист — как в контракте: keccak256("peremech.anonbox") mod FIELD.
export function zeroLeaf(keccak256Hex) {
    return BigInt(keccak256Hex) % FIELD;
}

// Дерево всех конвертов ящика, в порядке их номеров.
export class Tree {
    constructor(zero, leaves = []) {
        this.zeros = [zero];
        for (let i = 1; i <= LEVELS; i++) this.zeros.push(hash([this.zeros[i - 1], this.zeros[i - 1]]));
        this.layers = [leaves.map(BigInt)];
        this.rebuild();
    }

    rebuild() {
        for (let lvl = 0; lvl < LEVELS; lvl++) {
            const cur = this.layers[lvl];
            const up = [];
            for (let i = 0; i < cur.length; i += 2) {
                const left = cur[i];
                const right = i + 1 < cur.length ? cur[i + 1] : this.zeros[lvl];
                up.push(hash([left, right]));
            }
            this.layers[lvl + 1] = up;
        }
    }

    root() {
        const top = this.layers[LEVELS];
        return top.length ? top[0] : this.zeros[LEVELS];
    }

    path(index) {
        const elements = [];
        const indices = [];
        let idx = index;
        for (let lvl = 0; lvl < LEVELS; lvl++) {
            const sib = idx ^ 1;
            const layer = this.layers[lvl];
            elements.push(sib < layer.length ? layer[sib] : this.zeros[lvl]);
            indices.push(idx & 1);
            idx >>= 1;
        }
        return { elements, indices };
    }
}

// ---------------------------------------------------------------- чтение ящика из сети

// keccak256("Deposit(uint256,uint32,bytes)")
export const DEPOSIT_TOPIC = "0xf7aece2f04e9b2df9593af6e0e244158083f0012d7c99e33c74f5c3f42ac5fb4";

async function rpc(url, method, params) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const j = await res.json();
    if (j.error) throw new Error(method + ": " + j.error.message);
    return j.result;
}

// Конверт из записи Deposit: номер, отпечаток и письмо.
export function parseDeposit(log) {
    const data = fromHex(log.data);
    const word = (i) => bytesToBig(data.slice(i * 32, i * 32 + 32));
    const index = Number(word(0));
    const offset = Number(word(1));
    const len = Number(bytesToBig(data.slice(offset, offset + 32)));
    return {
        index,
        commitment: BigInt(log.topics[1]),
        envelope: data.slice(offset + 32, offset + 32 + len),
        block: Number(BigInt(log.blockNumber)),
    };
}

// Все конверты ящика с блока from. Узел отдаёт записи кусками — идём по частям.
export async function scanBox(url, box, from = 0, step = 100000) {
    const last = Number(BigInt(await rpc(url, "eth_blockNumber", [])));
    const out = [];
    for (let start = from; start <= last; start += step) {
        const end = Math.min(start + step - 1, last);
        const logs = await rpc(url, "eth_getLogs", [
            { address: box, topics: [DEPOSIT_TOPIC], fromBlock: "0x" + start.toString(16), toBlock: "0x" + end.toString(16) },
        ]);
        for (const l of logs) out.push(parseDeposit(l));
    }
    out.sort((a, b) => a.index - b.index);
    return { deposits: out, lastBlock: last };
}

// keccak256("Withdrawal(address,address,uint256,uint256,uint256[4])")
export const WITHDRAWAL_TOPIC = "0x646bfa35a1ca4981033db1b04af7bb6d8729a12ced3cb8cdd24c342dfb403665";

// Метки всех уже забранных конвертов ящика. Берём общий список выводов целиком,
// а не спрашиваем про свои метки: такой вопрос выдал бы узлу, какие конверты наши.
export async function scanSpent(url, box, from = 0, step = 100000) {
    const last = Number(BigInt(await rpc(url, "eth_blockNumber", [])));
    const spent = new Set();
    for (let start = from; start <= last; start += step) {
        const end = Math.min(start + step - 1, last);
        const logs = await rpc(url, "eth_getLogs", [
            { address: box, topics: [WITHDRAWAL_TOPIC], fromBlock: "0x" + start.toString(16), toBlock: "0x" + end.toString(16) },
        ]);
        for (const l of logs) {
            const data = fromHex(l.data);
            for (let i = 0; i < 4; i++) {
                const n = bytesToBig(data.slice(64 + i * 32, 96 + i * 32));
                if (n !== 0n) spent.add(n.toString());
            }
        }
    }
    return spent;
}

// ---------------------------------------------------------------- чтение ящика («лодка»)
//
// Ящик хранит конверты сам, по номерам, и общий список забранных меток. Поэтому
// не листаем историю сети: спрашиваем «сколько?» и забираем пачками. Время чтения
// не растёт со временем. Свои метки узлу не называем — берём общий список целиком.

const SEL_NEXT_INDEX = "0xfc7e9c6f";   // nextIndex()
const SEL_NOTES = "0x9c3e00a1";        // notes(uint256,uint256)
const SEL_SPENT_COUNT = "0x1a409b85";  // spentCount()
const SEL_SPENT_FROM = "0xa7fab284";   // spentFrom(uint256,uint256)
const PAGE = 200;

const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const at = (b, i) => bytesToBig(b.slice(i, i + 32));
async function call(url, to, data) {
    return fromHex(await rpc(url, "eth_call", [{ to, data }, "latest"]));
}
function pages(total) {
    const out = [];
    for (let from = 0; from < total; from += PAGE) out.push(from);
    return out;
}

// Все конверты ящика: [{index, commitment, envelope, time}].
export async function readBox(url, box) {
    const total = Number(at(await call(url, box, SEL_NEXT_INDEX), 0));
    const parts = await Promise.all(pages(total).map(async (from) => {
        const b = await call(url, box, SEL_NOTES + word(from) + word(PAGE));
        const oc = Number(at(b, 0)), ot = Number(at(b, 32)), oe = Number(at(b, 64));
        const n = Number(at(b, oc));
        const out = [];
        for (let i = 0; i < n; i++) {
            const base = oe + 32;
            const pos = base + Number(at(b, base + 32 * i));
            const len = Number(at(b, pos));
            out.push({
                index: from + i,
                commitment: at(b, oc + 32 + 32 * i),
                envelope: b.slice(pos + 32, pos + 32 + len),
                time: new Date(Number(at(b, ot + 32 + 32 * i)) * 1000),
            });
        }
        return out;
    }));
    return { deposits: parts.flat() };
}

// Метки всех уже забранных конвертов ящика.
export async function readSpent(url, box) {
    const total = Number(at(await call(url, box, SEL_SPENT_COUNT), 0));
    const spent = new Set();
    const parts = await Promise.all(pages(total).map((from) => call(url, box, SEL_SPENT_FROM + word(from) + word(PAGE))));
    for (const b of parts) {
        const o = Number(at(b, 0));
        const n = Number(at(b, o));
        for (let i = 0; i < n; i++) spent.add(at(b, o + 32 + 32 * i).toString());
    }
    return spent;
}

// Время блока — приблизительно, по двум опорным блокам: начала ящика и последнему.
// Спрашивать время каждого своего блока нельзя — это выдало бы узлу, какие блоки наши.
export async function blockClock(url, from) {
    const get = (n) => rpc(url, "eth_getBlockByNumber", [n, false]);
    const [a, b] = await Promise.all([get("0x" + Math.max(0, from).toString(16)), get("latest")]);
    const n0 = Number(BigInt(a.number)), t0 = Number(BigInt(a.timestamp));
    const n1 = Number(BigInt(b.number)), t1 = Number(BigInt(b.timestamp));
    const rate = n1 > n0 ? (t1 - t0) / (n1 - n0) : 0;
    return (block) => new Date((t0 + (block - n0) * rate) * 1000);
}

// ---------------------------------------------------------------- вывод

// Доказательство вывода до MAX_INPUTS конвертов. notes: [{index, commitment, blinding}].
export async function proveWithdraw(snarkjs, { keys, notes, tree, recipient, relayer, fee, wasm, zkey }) {
    if (!notes.length || notes.length > MAX_INPUTS) throw new Error("1..4 конверта за раз");
    const secret = BigInt(keys.secret);
    const blinding = [], enabled = [], pathElements = [], pathIndices = [], nullifiers = [];
    for (let i = 0; i < MAX_INPUTS; i++) {
        const n = notes[i];
        if (n) {
            const p = tree.path(n.index);
            blinding.push(n.blinding.toString());
            enabled.push("1");
            pathElements.push(p.elements.map(String));
            pathIndices.push(p.indices.map(String));
            nullifiers.push(nullifierOf(secret, n.commitment).toString());
        } else {
            blinding.push("0");
            enabled.push("0");
            pathElements.push(Array(LEVELS).fill("0"));
            pathIndices.push(Array(LEVELS).fill("0"));
            nullifiers.push("0");
        }
    }
    const input = {
        root: tree.root().toString(),
        nullifiers,
        recipient: BigInt(recipient).toString(),
        relayer: BigInt(relayer).toString(),
        fee: BigInt(fee).toString(),
        secret: secret.toString(),
        blinding,
        enabled,
        pathElements,
        pathIndices,
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    return {
        a: [proof.pi_a[0], proof.pi_a[1]],
        // Координаты второй точки в контракте идут в обратном порядке.
        b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
        c: [proof.pi_c[0], proof.pi_c[1]],
        root: input.root,
        nullifiers,
        publicSignals,
    };
}
