// Сборка программы «Кошелёк анонимного ящика»: файлы схемы и адреса ящиков
// вшиваются внутрь, на выходе — по файлу под Windows, Mac и Linux в build/desktop/.
//
//   BOX10=0x... BOX100=0x... FROM=<блок> [RPC=...] [CHAIN_ID=4217] [FEE_TOKEN=0x...] node build.mjs
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const env = process.env;
for (const k of ["BOX10", "BOX100", "FROM"]) if (!env[k]) throw new Error("нужно " + k);
fs.copyFileSync("../build/anonbox-wallet.js", "web/anonbox-wallet.js");
fs.copyFileSync("../build/withdraw_js/withdraw.wasm", "web/withdraw.wasm");
fs.copyFileSync("../build/withdraw.zkey", "web/withdraw.zkey");
fs.writeFileSync("web/defaults.json", JSON.stringify({
    rpc: env.RPC || "https://rpc.tempo.xyz",
    chain_id: Number(env.CHAIN_ID || 4217),
    fee_token: env.FEE_TOKEN || "0x20c00000000000000000000014f22ca97301eb73", // USDT0
    box10: env.BOX10,
    box100: env.BOX100,
    from: String(env.FROM),
}, null, 2));

const out = "../build/desktop";
fs.mkdirSync(out, { recursive: true });
const targets = [
    ["windows", "amd64", "anonbox-wallet-windows.exe"],
    ["darwin", "arm64", "anonbox-wallet-mac-apple-silicon"],
    ["darwin", "amd64", "anonbox-wallet-mac-intel"],
    ["linux", "amd64", "anonbox-wallet-linux"],
];
for (const [os, arch, name] of targets) {
    // Без -ldflags "-s -w": сжатую программу Защитник Windows принимает за троян.
    execFileSync("go", ["build", "-trimpath", "-o", out + "/" + name, "."],
        { stdio: "inherit", env: { ...env, GOOS: os, GOARCH: arch, CGO_ENABLED: "0" } });
    console.log("собрано: " + name);
}
