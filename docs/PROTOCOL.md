# zProtocol v1 — specifica del formato sul filo

Trasporto: flusso TCP. Tutti gli interi multi-byte sono **big-endian** salvo diversa indicazione.
Dopo l'handshake ogni byte sul filo è indistinguibile da rumore casuale.

## 1. Primitive

| Uso                      | Algoritmo                                   |
|--------------------------|---------------------------------------------|
| Scambio di chiavi        | X25519                                      |
| AEAD                     | ChaCha20-Poly1305 (nonce = `0x00000000 ‖ n` con `n` u64 little-endian) |
| Hash / KDF               | BLAKE2s, HMAC-BLAKE2s, HKDF di Noise (§4.3 del Noise Framework) |
| Offuscamento chiavi      | Elligator2 per Curve25519 (con punto di torsione casuale) |
| Derivazione della PSK    | scrypt (`n=2^14, r=8, p=1`, salt `"zprotocol/1 psk"`) → 32 byte |

## 2. Handshake

Pattern Noise **XXpsk0**, nome di protocollo
`zProtocol/1 Noise_XXpsk0_25519+Elligator2_ChaChaPoly_BLAKE2s`:

```
-> psk, e
<- e, ee, s, es
-> s, se
```

Regole particolari:

- Le chiavi effimere viaggiano come **rappresentanti Elligator2** da 32 byte (254 bit utili + 2 bit alti
  casuali). Nella trascrizione (`MixHash`/`MixKey`) entrano i 32 byte *come inviati*; il DH usa la
  coordinata `u` ottenuta decodificando il rappresentante.
- Il token `psk` esegue `MixKeyAndHash(PSK)` prima di `e`. In modalità PSK, ogni token `e` esegue anche
  `MixKey(rappresentante)` (regola di Noise per i modificatori `psk`).
- Il prologo è vuoto. Dopo ogni payload cifrato si esegue `MixHash(padding)`.
- Le chiavi statiche viaggiano cifrate (`EncryptAndHash`), quindi appaiono casuali.

### Messaggi

Ogni messaggio ha una **testa a lunghezza fissa**, che contiene la lunghezza del padding, seguita dal
**padding** (byte casuali, lunghezza `0..max_pad`, `max_pad` ≤ 4096; default 512).

| Messaggio | Verso | Struttura                                                                 | Testa  |
|-----------|-------|---------------------------------------------------------------------------|--------|
| msg1      | C → S | `rep_e(32) ‖ AEAD(ver(1) ‖ pad_len(2) ‖ timestamp(8))(+16) ‖ padding`      | 59 B   |
| msg2      | S → C | `rep_e(32) ‖ AEAD(s_pub)(32+16) ‖ AEAD(ver(1) ‖ pad_len(2))(+16) ‖ padding` | 99 B   |
| msg3      | C → S | `AEAD(s_pub)(32+16) ‖ AEAD(ver(1) ‖ pad_len(2))(+16) ‖ padding`            | 67 B   |

- `ver` = 1. `timestamp` = secondi Unix UTC (u64).
- Il lettore legge la testa (lunghezza nota), decifra, ricava `pad_len`, poi legge e scarta il padding
  (dopo averlo inserito nell'hash).

### Regole del server (resistenza al probing)

Il server **non invia nulla** finché msg1 non è autenticato. In caso di *qualsiasi* errore
(tag non valido, versione errata, timestamp fuori finestra, replay, msg3 non valido, timeout) non invia
alcun byte: continua a leggere e scartare per un tempo casuale (`reject_delay`, default 3–12 s, max 64 KiB)
e poi chiude la connessione.

- **Finestra del timestamp**: `|now − timestamp| ≤ max_clock_skew` (default 120 s).
- **Anti-replay**: i `rep_e` di msg1 già autenticati si ricordano per `2 × max_clock_skew + 5` s.
- **Timeout di handshake**: 10 s (default).

### Chiavi di sessione

Alla fine dell'handshake (`ck` = chaining key finale):

```
k1, k2 = HKDF(ck, "", 2)                       # Split() di Noise
m1, m2 = HKDF(ck, "zprotocol/1 length-mask keys", 2)
iniziatore:   invio = k1, ricezione = k2, maschera invio = m1, maschera ricezione = m2
risponditore: invio = k2, ricezione = k1, maschera invio = m2, maschera ricezione = m1
```

Il valore `h` finale è l'*handshake hash* (utilizzabile come channel binding).

## 3. Record

Dopo msg3 il flusso è una sequenza di record per direzione:

```
+-----------------+--------------------------------------------+
| len_enc (2 B)   | ciphertext (len B)                         |
+-----------------+--------------------------------------------+
len_enc    = len XOR BLAKE2s(key = chiave_maschera, msg = n (u64 BE), digest_size = 2)
ciphertext = ChaCha20-Poly1305(chiave, nonce = n, ad = len_enc,
                               plaintext = tipo(1) ‖ lunghezza_dati(2) ‖ dati ‖ padding)
```

- `n` è il contatore del record nella direzione (parte da 0, +1 per record, mai riusato; non si azzera al rekey).
- `len` = lunghezza di `ciphertext` (incluso il tag da 16 B); valido tra 19 e `3 + 16384 + 4096 + 16`.
- `dati` ≤ 16384 byte; `padding` = 0..`max_pad` zeri (cifrati, quindi casuali sul filo), `max_pad` ≤ 4096.
- Un record che non autentica (manomesso, riordinato, ripetuto) è un errore fatale: si chiude il flusso.

### Tipi di record

| Valore | Nome  | Significato                                                              |
|--------|-------|--------------------------------------------------------------------------|
| 0      | DATA  | dati applicativi                                                          |
| 1      | PAD   | traffico di copertura, scartato dal ricevente                            |
| 2      | REKEY | dopo questo record il mittente usa `k = REKEY(k)`; il ricevente fa lo stesso |
| 3      | CLOSE | il mittente non invierà altri dati (half-close autenticato)              |
| 4      | PING  | richiede un PONG con gli stessi dati                                     |
| 5      | PONG  | risposta a PING                                                          |

Tipi sconosciuti sono ignorati (estensibilità). La fine del flusso TCP **senza** CLOSE è trattata
come possibile troncamento (`TruncatedStream`).

### Rekey

Dopo `rekey_after` record (default 2^20) il mittente emette un record REKEY sotto la vecchia chiave e poi
passa a `REKEY(k) = primi 32 byte di ENCRYPT(k, nonce = 2^64−1, ad = "", plaintext = 32 zeri)`.
Il ricevente applica la stessa trasformazione quando decifra il record REKEY.

## 4. Elligator2 (chiavi effimere)

- Curva25519: `v² = u³ + 486662·u² + u` su `p = 2^255 − 19`, non-residuo `2`.
- **Decodifica** (`rep` → `u`): `r = rep & (2^254−1)`; `w = −A / (1 + 2r²)`;
  `u = w` se `w³ + A·w² + w` è residuo quadratico, altrimenti `u = −w − A`.
- **Generazione**: si estrae una privata casuale, si calcola la pubblica `P = a·G`, si somma un punto di
  torsione casuale (ordine 8), e si accetta solo se `−2u(u+A)` è residuo quadratico (circa 1 volta su 2).
  Il rappresentante è `min(r, p−r)` con `r = √(−u/(2(u+A)))` o `√(−(u+A)/(2u))` scelto a caso, più 2 bit alti casuali.
- Il DH ignora la componente di torsione perché lo scalare X25519 è multiplo di 8.

## 5. Estensioni previste

Multiplexing di stream (nuovi tipi di record), trasporto UDP, nuovi profili di padding/timing e una
versione 2 del handshake con negoziazione di parametri nel payload cifrato.
