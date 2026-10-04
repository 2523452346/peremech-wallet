// Кошелёк peremech без сайта — программа для компьютера.
//
// Нужна на случай, если сайта peremech больше нет. Запускаешь файл — открывается
// страница у тебя на компьютере (127.0.0.1). В ней два раздела:
//
//   - Wallet — обычный баланс. Открывается запасным файлом-ключом кошелька
//     (private_key_peremech.txt, скачивался при настройке кошелька на сайте).
//     Вывод на любой адрес Tempo: Хранилище принимает его только от этого ключа.
//   - Anonymous box — анонимные донаты. Открывается файлом-ключом ящика; ящики
//     читаются прямо из сети, доказательство вывода считается на странице.
//
// Газ за оба вида выводов платит кошелёк для газа: его создаёт программа или
// ты вставляешь ключ своего кошелька, где уже есть пара центов USDT0. Ключ
// лежит только рядом с программой, в файле anonbox-wallet-gas-key.txt.
// За вывод обычного баланса кошелёк для газа платит как «плательщик газа» Tempo:
// транзакцию подписывает запасной ключ, газ — отдельной подписью этот кошелёк.
//
// Ни одного обращения к сайту peremech здесь нет: только к открытому узлу Tempo.
package main

import (
	"context"
	"crypto/ecdsa"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

//go:embed web
var webFiles embed.FS

// Настройки сети и ящиков — web/defaults.json, кладётся при сборке.
type settings struct {
	RPC      string `json:"rpc"`
	ChainID  int64  `json:"chain_id"`
	FeeToken string `json:"fee_token"`
	Box10    string `json:"box10"`
	Box100   string `json:"box100"`
	From     string `json:"from"`
}

const (
	gasKeyFile = "anonbox-wallet-gas-key.txt"
	txGas      = uint64(3_000_000)
	// Потолок цены газа: выше — сеть перегружена, лучше подождать.
	maxFeeCap = int64(30_000_000_000)
	tipBonus  = int64(3_000_000_000)
)

var (
	cfg    settings
	hex32  = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	addrRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

	mu     sync.Mutex
	gasKey *ecdsa.PrivateKey // кошелёк для газа; nil — ещё не выбран

	// Открытый кошелёк (обычный баланс): запасной ключ, номер счёта, Хранилище.
	walletKey     *ecdsa.PrivateKey
	walletUser    string
	walletCustody string
)

func main() {
	raw, err := webFiles.ReadFile("web/defaults.json")
	if err != nil {
		log.Fatal("нет настроек ящиков в программе")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal("настройки ящиков испорчены")
	}
	gasKey = loadGasKey()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := ln.Addr().String()
	sub, _ := fs.Sub(webFiles, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/gas", handleGas)
	mux.HandleFunc("/api/gas/create", handleGasCreate)
	mux.HandleFunc("/api/gas/import", handleGasImport)
	mux.HandleFunc("/api/send", handleSend)
	mux.HandleFunc("/api/wallet/open", handleWalletOpen)
	mux.HandleFunc("/api/wallet/withdraw", handleWalletWithdraw)

	url := "http://" + addr + "/"
	fmt.Println("Кошелёк peremech открыт: " + url)
	fmt.Println("Окно браузера откроется само. Закрой эту программу, когда закончишь.")
	go openBrowser(url)
	log.Fatal(http.Serve(ln, onlyOwnPage(mux, addr)))
}

// Команды принимаются только со своей же страницы: чужой сайт в браузере не
// сможет попросить программу отправить что-то от твоего имени.
func onlyOwnPage(next http.Handler, addr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+addr {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func parseKey(s string) (*ecdsa.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	if !hex32.MatchString(s) {
		return nil, fmt.Errorf("a private key is 0x + 64 characters")
	}
	return gethcrypto.HexToECDSA(s[2:])
}

func loadGasKey() *ecdsa.PrivateKey {
	b, err := os.ReadFile(filepath.Join(exeDir(), gasKeyFile))
	if err != nil {
		return nil
	}
	k, err := parseKey(string(b))
	if err != nil {
		log.Printf("файл %s испорчен: %v", gasKeyFile, err)
		return nil
	}
	return k
}

func saveGasKey(k *ecdsa.PrivateKey) error {
	text := "0x" + hex.EncodeToString(gethcrypto.FromECDSA(k)) + "\n"
	return os.WriteFile(filepath.Join(exeDir(), gasKeyFile), []byte(text), 0600)
}

func addressOf(k *ecdsa.PrivateKey) gethcommon.Address {
	return gethcrypto.PubkeyToAddress(k.PublicKey)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func rpcCall(ctx context.Context, method string, params ...interface{}) (interface{}, error) {
	resp, err := client.New(cfg.RPC).SendRequest(ctx, method, params...)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Error != nil {
		return nil, fmt.Errorf("%v", resp.Error)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty answer")
	}
	return resp.Result, nil
}

func hexBig(v interface{}) *big.Int {
	s, _ := v.(string)
	n, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if n == nil {
		return new(big.Int)
	}
	return n
}

func word(b []byte) string { return fmt.Sprintf("%064x", new(big.Int).SetBytes(b)) }

// Число из контракта по готовому вызову.
func callUint(ctx context.Context, to, data string) (*big.Int, error) {
	res, err := rpcCall(ctx, "eth_call", map[string]string{"to": to, "data": data}, "latest")
	if err != nil {
		return nil, err
	}
	return hexBig(res), nil
}

func tokenBalance(ctx context.Context, owner gethcommon.Address) string {
	v, err := callUint(ctx, cfg.FeeToken, "0x70a08231"+word(owner.Bytes()))
	if err != nil {
		return "?"
	}
	return v.String()
}

// ---------------------------------------------------------------- кошелёк для газа

// GET /api/gas — выбран ли кошелёк для газа, его адрес и сколько на нём USDT0.
func handleGas(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	k := gasKey
	mu.Unlock()
	if k == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"configured": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]interface{}{"configured": true, "address": addressOf(k).Hex(), "balance": tokenBalance(ctx, addressOf(k))})
}

// POST /api/gas/create — создать новый кошелёк для газа.
func handleGasCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	k, err := gethcrypto.GenerateKey()
	if err == nil {
		err = saveGasKey(k)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	mu.Lock()
	gasKey = k
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"address": addressOf(k).Hex()})
}

// POST /api/gas/import {key} — свой кошелёк, где уже есть деньги на газ.
func handleGasImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	k, err := parseKey(body.Key)
	if err == nil {
		err = saveGasKey(k)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	mu.Lock()
	gasKey = k
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"address": addressOf(k).Hex()})
}

// ---------------------------------------------------------------- отправка

// sendTx — подписать и отправить вызов. sender — тот, от чьего имени вызов;
// feePayer — кто платит газ (nil — платит сам sender). Сначала сухой прогон:
// если сеть вызов не примет, газ на него не тратится.
func sendTx(ctx context.Context, sender, feePayer *ecdsa.PrivateKey, to string, data []byte) (string, error) {
	from := addressOf(sender).Hex()
	if _, err := rpcCall(ctx, "eth_call", map[string]string{"from": from, "to": to, "data": "0x" + hex.EncodeToString(data)}, "latest"); err != nil {
		return "", fmt.Errorf("the network would reject this: %v", err)
	}
	rpc := client.New(cfg.RPC)
	// Транзакции Tempo этого типа ведут счётчик по «дорожкам»; нулевую сеть не
	// принимает. Берём свою постоянную дорожку.
	nonceKey := new(big.Int).SetBytes(gethcrypto.Keccak256([]byte("anonbox-wallet")))
	nonce, err := rpc.GetNonce(ctx, from, nonceKey)
	if err != nil {
		return "", err
	}
	block, err := rpcCall(ctx, "eth_getBlockByNumber", "latest", false)
	if err != nil {
		return "", err
	}
	bm, _ := block.(map[string]interface{})
	baseFee := hexBig(bm["baseFeePerGas"])
	maxFee := new(big.Int).Add(baseFee, big.NewInt(tipBonus))
	if maxFee.Cmp(big.NewInt(maxFeeCap)) > 0 {
		maxFee = big.NewInt(maxFeeCap)
	}
	tip := new(big.Int).Sub(maxFee, baseFee)
	if tip.Sign() < 0 {
		tip = new(big.Int)
	}
	// Хватит ли кошельку для газа на плату сети. Иначе сеть отвечает невнятным
	// «insufficient funds for gas», а человеку нужно понятное «пополни».
	payer := sender
	if feePayer != nil {
		payer = feePayer
	}
	need := new(big.Int).Mul(new(big.Int).SetUint64(txGas), maxFee)
	need.Div(need.Add(need, big.NewInt(999_999_999_999)), big.NewInt(1_000_000_000_000)) // в единицах USDT0
	if have, err := callUint(ctx, cfg.FeeToken, "0x70a08231"+word(addressOf(payer).Bytes())); err == nil && have.Cmp(need) < 0 {
		return "", errFeeWalletEmpty(have, need)
	}

	b := transaction.NewBuilder(big.NewInt(cfg.ChainID)).
		SetMaxFeePerGas(maxFee).
		SetMaxPriorityFeePerGas(tip).
		SetNonce(nonce).
		SetNonceKey(nonceKey).
		SetGas(txGas).
		SetFeeToken(gethcommon.HexToAddress(cfg.FeeToken)).
		AddCall(gethcommon.HexToAddress(to), big.NewInt(0), data)
	if feePayer != nil {
		b = b.SetSponsored(true)
	}
	tx := b.Build()
	if err := transaction.SignTransaction(tx, signer.NewSignerFromKey(sender)); err != nil {
		return "", err
	}
	if feePayer != nil {
		if err := transaction.AddFeePayerSignature(tx, signer.NewSignerFromKey(feePayer)); err != nil {
			return "", err
		}
	}
	raw, err := transaction.Serialize(tx, nil)
	if err != nil {
		return "", err
	}
	hash, err := rpc.SendRawTransaction(ctx, raw)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient funds") {
			return "", errFeeWalletEmpty(nil, need)
		}
		return "", err
	}
	for i := 0; i < 40; i++ {
		res, err := rpcCall(ctx, "eth_getTransactionReceipt", hash)
		if err == nil && res != nil {
			rm, _ := res.(map[string]interface{})
			if st, _ := rm["status"].(string); st == "0x1" {
				return hash, nil
			} else if st != "" {
				return hash, fmt.Errorf("the transaction failed in the network")
			}
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return hash, nil
}

func errFeeWalletEmpty(have, need *big.Int) error {
	usd := func(v *big.Int) string {
		f, _ := new(big.Float).Quo(new(big.Float).SetInt(v), big.NewFloat(1e6)).Float64()
		return fmt.Sprintf("$%.4f", f)
	}
	msg := "The fee wallet does not have enough to pay the network fee"
	if have != nil {
		msg += " (it has " + usd(have) + ", this needs up to " + usd(need) + ")"
	}
	return fmt.Errorf("%s. Put a few cents of USDT0 on it (Tempo network), press Refresh balance and try again", msg)
}

func needGas(w http.ResponseWriter) *ecdsa.PrivateKey {
	mu.Lock()
	k := gasKey
	mu.Unlock()
	if k == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Choose a fee wallet first (step 1)."})
	}
	return k
}

// POST /api/send {to, data} — отправить готовый вывод из ящика с кошелька для газа.
// Только в ящики из настроек.
func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body struct {
		To   string `json:"to"`
		Data string `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	if !strings.EqualFold(body.To, cfg.Box10) && !strings.EqualFold(body.To, cfg.Box100) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not_a_box"})
		return
	}
	data, err := hex.DecodeString(strings.TrimPrefix(body.Data, "0x"))
	if err != nil || len(data) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_data"})
		return
	}
	k := needGas(w)
	if k == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	hash, err := sendTx(ctx, k, nil, body.To, data)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "tx": hash})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "done", "tx": hash})
}

// ---------------------------------------------------------------- обычный баланс

// POST /api/wallet/open {private_key, user, custody} — открыть кошелёк запасным
// файлом-ключом. Программа сверяет, что ключ — действительно запасной ключ этого
// счёта в Хранилище, и показывает баланс.
func handleWalletOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body struct {
		PrivateKey string `json:"private_key"`
		User       string `json:"user"`
		Custody    string `json:"custody"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	k, err := parseKey(body.PrivateKey)
	if err != nil || !hex32.MatchString(body.User) || !addrRe.MatchString(body.Custody) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "This is not a peremech backup key file."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	userWord := strings.TrimPrefix(strings.ToLower(body.User), "0x")
	// recoveryOf(bytes32) — кто запасной ключ этого счёта.
	rec, err := callUint(ctx, body.Custody, "0x"+hex.EncodeToString(gethcrypto.Keccak256([]byte("recoveryOf(bytes32)"))[:4])+userWord)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The network did not answer: " + err.Error()})
		return
	}
	if gethcommon.BigToAddress(rec) != addressOf(k) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "This key is not the backup key of this account."})
		return
	}
	avail, err := callUint(ctx, body.Custody, "0x"+hex.EncodeToString(gethcrypto.Keccak256([]byte("available(bytes32)"))[:4])+userWord)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The network did not answer: " + err.Error()})
		return
	}
	mu.Lock()
	walletKey, walletUser, walletCustody = k, "0x"+userWord, body.Custody
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"balance": avail.String()})
}

// POST /api/wallet/withdraw {to, amount} — вывести обычный баланс (amount — в
// миллионных долях доллара). Вызов подписывает запасной ключ, газ платит
// кошелёк для газа.
func handleWalletWithdraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body struct {
		To     string `json:"to"`
		Amount string `json:"amount"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(body.Amount), 10)
	if !addrRe.MatchString(strings.TrimSpace(body.To)) || !ok || amount.Sign() <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Check the address and the amount."})
		return
	}
	mu.Lock()
	k, user, custody := walletKey, walletUser, walletCustody
	mu.Unlock()
	if k == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Open your wallet with the backup key file first."})
		return
	}
	gas := needGas(w)
	if gas == nil {
		return
	}
	// withdrawByRecovery(bytes32 user, address to, uint256 amount)
	sel := gethcrypto.Keccak256([]byte("withdrawByRecovery(bytes32,address,uint256)"))[:4]
	data, _ := hex.DecodeString(hex.EncodeToString(sel) +
		strings.TrimPrefix(user, "0x") +
		word(gethcommon.HexToAddress(body.To).Bytes()) +
		word(amount.Bytes()))
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	// Газ платит кошелёк для газа; если это и есть запасной ключ — платит сам.
	var feePayer *ecdsa.PrivateKey
	if addressOf(gas) != addressOf(k) {
		feePayer = gas
	}
	hash, err := sendTx(ctx, k, feePayer, custody, data)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "tx": hash})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "done", "tx": hash})
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
