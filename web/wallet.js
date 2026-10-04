// Файл для получателя: ключи, чтение ящика, вскрытие писем, доказательство вывода.
import * as snarkjs from "snarkjs";
import * as box from "../lib/anonbox.js";
window.AnonBoxWallet = { ...box, prove: (args) => box.proveWithdraw(snarkjs, args) };
