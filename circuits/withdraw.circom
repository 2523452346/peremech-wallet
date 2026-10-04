pragma circom 2.1.9;

// Вывод из анонимного ящика.
//
// Доказывает: «вот эти конверты лежат в ящике, они мои, и я забираю их впервые»,
// не говоря, какие именно это конверты.
//
// Конверт в ящике — это только отпечаток commitment = Poseidon(owner, blinding):
//   owner    = Poseidon(secret) — открытая половина ключа получателя, лежит в его профиле;
//   blinding — случайное число, известное только получателю (лежит в зашифрованном
//              письме к конверту).
// Суммы в конверте нет: у каждого ящика свой номинал, все конверты в нём одинаковые.
// Иначе отправитель мог бы вписать в конверт любую сумму.
//
// Метка забора (nullifier) = Poseidon(secret, commitment). Ящик помнит метки и второй
// раз тот же конверт не отдаёт. По метке нельзя понять, какой это конверт: для этого
// нужен secret.
//
// За один вывод можно забрать до nIns конвертов. Незанятые места — enabled = 0,
// их метка обязана быть нулём, и ящик их пропускает.
//
// Открытые входы (их видит ящик): root, nullifiers[nIns], recipient, relayer, fee.
// recipient/relayer/fee зашиты в доказательство, поэтому тот, кто доставляет вывод
// в сеть, не может подменить ни адрес получателя, ни свою плату.

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Корень дерева Меркла по листу и пути. pathIndices[i] = 0 — лист слева, 1 — справа.
template MerkleRoot(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels];
    signal cur[levels + 1];
    cur[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== cur[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== cur[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        cur[i + 1] <== hashers[i].out;
    }
    root <== cur[levels];
}

template Withdraw(levels, nIns) {
    // Открытые.
    signal input root;
    signal input nullifiers[nIns];
    signal input recipient;
    signal input relayer;
    signal input fee;

    // Тайные.
    signal input secret;
    signal input blinding[nIns];
    signal input enabled[nIns];
    signal input pathElements[nIns][levels];
    signal input pathIndices[nIns][levels];

    component ownerHash = Poseidon(1);
    ownerHash.inputs[0] <== secret;

    component commit[nIns];
    component nul[nIns];
    component tree[nIns];
    component rootOk[nIns];

    for (var i = 0; i < nIns; i++) {
        enabled[i] * (1 - enabled[i]) === 0;

        commit[i] = Poseidon(2);
        commit[i].inputs[0] <== ownerHash.out;
        commit[i].inputs[1] <== blinding[i];

        tree[i] = MerkleRoot(levels);
        tree[i].leaf <== commit[i].out;
        for (var j = 0; j < levels; j++) {
            tree[i].pathElements[j] <== pathElements[i][j];
            tree[i].pathIndices[j] <== pathIndices[i][j];
        }
        // Занятое место обязано быть настоящим конвертом из этого ящика.
        rootOk[i] = ForceEqualIfEnabled();
        rootOk[i].enabled <== enabled[i];
        rootOk[i].in[0] <== tree[i].root;
        rootOk[i].in[1] <== root;

        nul[i] = Poseidon(2);
        nul[i].inputs[0] <== secret;
        nul[i].inputs[1] <== commit[i].out;
        // Незанятое место — метка ноль, занятое — настоящая метка.
        nullifiers[i] === enabled[i] * nul[i].out;
    }

    // Привязываем открытые входы к доказательству: без этих строк компилятор
    // выбросил бы их, и подменить получателя стало бы можно.
    signal recipientSq <== recipient * recipient;
    signal relayerSq <== relayer * relayer;
    signal feeSq <== fee * fee;
}

component main {public [root, nullifiers, recipient, relayer, fee]} = Withdraw(20, 4);
