# zProtocol

Protocollo di trasporto **cifrato e offuscato** tra client e server (o tra peer), su TCP grezzo.
Non usa HTTP(S) né WebSocket: sul filo non c'è nessun header, magic byte o handshake in chiaro.

> **Stato: prototipo (v0.1).** La crittografia usa solo primitive collaudate (X25519, ChaCha20-Poly1305,
> BLAKE2s) assemblate secondo il Noise Framework, ma **la composizione non è stata sottoposta ad audit**.
> Non usarlo per proteggere dati davvero sensibili finché non è stato rivisto da un crittografo.

## Caratteristiche

- **Handshake Noise `XXpsk0`** con X25519 / ChaCha20-Poly1305 / BLAKE2s: autenticazione reciproca,
  forward secrecy, protezione dal replay.
- **Chiavi effimere Elligator2**: anche i primi byte dell'handshake sono indistinguibili da rumore casuale.
- **Nessun byte riconoscibile**: lunghezza dei record cifrata (maschera), padding casuale su ogni record
  e su ogni messaggio di handshake, traffico di copertura opzionale.
- **Resistenza al probing attivo**: senza la PSK un client non ottiene *nessuna* risposta
  (il server resta muto e chiude dopo un tempo casuale). Timestamp + cache anti-replay su msg1.
- **Identità e pinning**: ogni nodo ha una chiave statica; il client può fissare la chiave del server,
  il server può avere una allow-list di client.
- **Rekey automatico** delle chiavi di trasporto e half-close autenticato (niente troncamenti silenziosi).
- **P2P a livello di nodo**: ruoli simmetrici (chiunque può ascoltare o connettersi), identità = chiave
  pubblica, `peer_id` derivato dalla chiave. Include una chat peer-to-peer da terminale.
- Un **tunnel TCP** pronto all'uso (port forwarding cifrato e offuscato).

## Struttura

```
src/zprotocol/
  crypto.py      primitive: HKDF, CipherState, SymmetricState (Noise)
  elligator.py   chiavi effimere con rappresentazione Elligator2
  handshake.py   macchina a stati del handshake (XXpsk0)
  record.py      framing dei record: lunghezza mascherata, padding, rekey
  session.py     Connection asincrona, handshake su stream, server (serve)
  tunnel.py      port forwarding TCP sopra zProtocol
  chat.py        chat P2P da terminale
  identity.py    chiavi statiche e peer_id
  config.py      Config e derive_psk
  cli.py         comando `zprotocol`
docs/PROTOCOL.md specifica del formato sul filo
tests/           44 test (crittografia, handshake, record, rete, offuscamento, CLI)
```

## Installazione

Richiede Python ≥ 3.11.

```bash
pip install -e ".[dev]"
pytest -q
```

## Avvio rapido: tunnel

Su **server** e **client** genera una identità ciascuno; sul server genera la PSK e copiala (fuori banda)
sul client.

```bash
# server
zprotocol keygen --out server.key        # stampa la pubkey: dalla al client
zprotocol genpsk > psk.txt               # passphrase condivisa

# client
zprotocol keygen --out client.key
```

Server: ascolta su 4443 e inoltra ogni sessione a un servizio locale (qui un web server su 8080).

```bash
zprotocol serve --listen 0.0.0.0:4443 --forward 127.0.0.1:8080 \
  --identity server.key --psk-file psk.txt
```

Client: apre la porta locale 9000 e la collega al server, verificandone la chiave pubblica.

```bash
zprotocol connect --listen 127.0.0.1:9000 --server IP_SERVER:4443 \
  --identity client.key --psk-file psk.txt --server-key <PUBKEY_SERVER_HEX>
curl http://127.0.0.1:9000/
```

Opzioni utili: `--allow <PUBKEY_CLIENT>` / `--allow-file` sul server (solo client autorizzati),
`--max-pad N` (padding massimo per record), `--cover MIN,MAX` (traffico di copertura),
`ZPROTOCOL_PSK` come variabile d'ambiente per non esporre la PSK in `ps`.

## Chat peer-to-peer

```bash
# nodo A
zprotocol chat --listen 0.0.0.0:5000 --identity a.key --psk-file psk.txt
# nodo B
zprotocol chat --connect IP_A:5000 --identity b.key --psk-file psk.txt --peer-key <PUBKEY_A_HEX>
```

## Uso come libreria

```python
import asyncio
from zprotocol import Config, Identity, derive_psk, open_connection, serve

psk = derive_psk("la-nostra-passphrase")          # una volta sola (scrypt)

async def handler(conn):                           # lato server: una Connection per client
    while data := await conn.recv():               # b"" = il peer ha chiuso
        await conn.send(data.upper())

async def main():
    server_cfg = Config(psk=psk, identity=Identity.load_or_create("server.key"))
    server = await serve(handler, "127.0.0.1", 4443, server_cfg)

    client_cfg = Config(psk=psk, identity=Identity.generate(),
                        verify_peer=lambda key: key == server_cfg.identity.public)
    conn = await open_connection("127.0.0.1", 4443, client_cfg)
    await conn.send(b"ciao")
    print(await conn.recv())                       # b"CIAO"
    await conn.close()
    server.close()

asyncio.run(main())
```

## Come funziona (in breve)

1. **msg1** `→ psk, e`: rappresentante Elligator2 dell'effimera (32 byte casuali) + payload cifrato con una
   chiave derivata dalla PSK (versione, lunghezza del padding, timestamp) + padding.
   Il server verifica il tag AEAD: se non torna, **non risponde**.
2. **msg2** `← e, ee, s, es` e **msg3** `→ s, se`: scambio delle identità statiche (già cifrate) e derivazione
   delle chiavi di sessione.
3. **Record**: `[lunghezza ⊕ maschera: 2 B][AEAD(tipo | lunghezza_dati | dati | padding)]`, con nonce a
   contatore, rekey periodico e tipi DATA / PAD / REKEY / CLOSE / PING / PONG.

Dettagli byte per byte in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Cosa protegge e cosa no

Protegge: confidenzialità e integrità del traffico, autenticazione reciproca dei nodi, forward secrecy,
replay, probing attivo da parte di chi non conosce la PSK, riconoscimento del protocollo tramite firme
statiche sui primi byte.

**Non** protegge da:

- **Analisi del traffico**: dimensioni e tempi sono solo mascherati (padding/copertura), non nascosti.
  Un osservatore può comunque vedere che c'è una connessione TCP verso quell'IP:porta.
- **Euristiche anti-"flussi completamente casuali"**: alcuni sistemi di censura bloccano proprio i
  protocolli senza alcun pattern riconoscibile (è il limite noto di obfs4/Shadowsocks). Se è il tuo caso
  serve un trasporto che imiti un protocollo reale.
- **Compromissione della PSK + chiave statica** di un endpoint, o malware sui nodi.
- **Clock sbagliato**: msg1 contiene un timestamp; con più di `max_clock_skew` (120 s) di scarto il client
  viene ignorato in silenzio.
- **Esaurimento di risorse** (DoS): non c'è ancora un limite di connessioni né rate limiting.

## Roadmap

- Multiplexing di più stream su una sessione (oggi: una sessione per connessione TCP).
- Trasporto UDP (stile WireGuard/QUIC) e NAT traversal con UDP hole punching.
- Scoperta dei peer (nodo di rendezvous, poi DHT) per un vero P2P senza indirizzi noti.
- Profili di traffic shaping (distribuzioni di dimensioni/tempi) e trasporti "mimetici" collegabili.
- Rotazione della PSK, limiti di connessioni, rate limiting, fuzzing del parser.
- Audit crittografico esterno.

## Licenza

Nessuna licenza è inclusa: aggiungi quella che preferisci (es. `LICENSE` MIT/Apache-2.0) prima di pubblicare.
