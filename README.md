# peremech wallet

A desktop program for getting your money out of peremech **without the peremech website**.
If the site is down or gone forever, your money is still yours: the program talks
directly to the Tempo network and nothing else.

One file, no installation. Windows, macOS (Apple Silicon and Intel) and Linux.
It opens a page in your browser that only you can see (it listens on 127.0.0.1).

## What it does

1. **Fee wallet.** Every withdrawal costs a network fee of a fraction of a cent in USDT0.
   Create a new fee wallet in the program and put a few cents on it, or paste the private
   key of a Tempo wallet you already have. The key is saved next to the program
   in `anonbox-wallet-gas-key.txt` and never leaves your computer.
2. **Wallet.** Your regular peremech balance. Open the backup key file you downloaded
   when you set up your wallet (`private_key_peremech.txt`), enter a Tempo address and
   an amount. The withdrawal is signed by your backup key (`withdrawByRecovery` in the
   custody contract); the fee wallet pays the network fee as Tempo fee payer, so the
   backup key itself needs no funds.
3. **Anonymous box.** Anonymous donations. Open your box key file, the program reads
   the envelopes straight from the box contract (it keeps every envelope, numbered) and withdraws them with a zero-knowledge proof (Groth16,
   up to 4 envelopes per proof). Nobody, including peremech, can link the sender's
   wallet to yours directly.

Only you sign your transactions. peremech cannot move your money and cannot stop you
from withdrawing it.

## Status: trial

The anonymous box contracts on Tempo mainnet are a **trial deployment**:

- box $10: `0xb107cD1A07ACbd967cd412b1172519F498Dac9bB`
- box $100: `0x7f004788283b57331E7911578AF0e576a3c5286D`
- first block: `42933827`

The proving key (`build/withdraw.zkey`) comes from a single-contributor setup. Before the
real launch there will be a multi-party ceremony, new box contracts and an external audit.
Do not treat the trial boxes as final.

## Layout

| Folder | What |
|---|---|
| `desktop/` | The program (Go). `build.mjs` builds it for all systems. |
| `contracts/` | Solidity: the custody contract (`PeremechCustodyV3.sol`) and the anonymous box (`anonbox/`). |
| `circuits/` | The withdrawal circuit (circom). |
| `lib/`, `web/` | Envelope encryption, scanning and proof code used by the program and the site. |
| `wallet/` | The same wallet as a plain web page (MetaMask variant). |
| `build/` | Circuit files: `withdraw.wasm`, `withdraw.zkey`, `vkey.json`. |

## Build it yourself

You need Go 1.27+ and Node.js 20+.

```
npm install
npm run build:js
cd desktop
BOX10=0x1Cd288eB65A086E5743dd3E1516735DD2D5a3A12 BOX100=0x838e4eB98D259B63C74F0f13BC411D62705783eA FROM=42933827 node build.mjs
```

The programs appear in `build/desktop/`.

On Windows the first run may show "unknown publisher" (the program is not code-signed):
click "More info" → "Run anyway". On macOS: right-click → Open.
