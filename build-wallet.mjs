// Собирает пакет кошелька без сайта: build/wallet/ — страница, код, файлы схемы
// и адреса ящиков. Пакет можно выложить куда угодно или раздать архивом.
//
//   BOX10=0x... BOX100=0x... FROM=<блок> RPC=https://rpc.tempo.xyz node build-wallet.mjs
import fs from "node:fs";

const out = "build/wallet";
fs.mkdirSync(out, { recursive: true });
fs.copyFileSync("wallet/index.html", out + "/index.html");
fs.copyFileSync("build/anonbox-wallet.js", out + "/anonbox-wallet.js");
fs.copyFileSync("build/withdraw_js/withdraw.wasm", out + "/withdraw.wasm");
fs.copyFileSync("build/withdraw.zkey", out + "/withdraw.zkey");
const d = {
    rpc: process.env.RPC || "https://rpc.tempo.xyz",
    box10: process.env.BOX10 || "",
    box100: process.env.BOX100 || "",
    from: process.env.FROM || "0",
};
fs.writeFileSync(out + "/defaults.js", "window.ANONBOX_DEFAULTS = " + JSON.stringify(d, null, 2) + ";\n");
console.log("собрано в " + out, d);
