XKore1 Checksum Suite
======================
Conjunto de ferramentas para calcular e injetar checksums do Ragnarok Online usando hooks no cliente, ponte via pipes e plugin do OpenKore.

Componentes principais
----------------------
1) `src_xkore/main.go` (DLL/ASI no cliente RO)  
   - Carrega configuração de `xkore1_config.txt` (cria padrão se faltar) e permite overrides com variáveis `XKORE1_*`.  
   - Injeta hooks em `send`/`recv` do cliente, calcula seed/checksum chamando funções nativas (`CHECKSUM`/`SEED`).  
   - Expõe dois named pipes por instância (`checksum_req_<clientID>`, `checksum_resp_<clientID>`) e envia heartbeats no pipe de controle `\\.\pipe\checksum_control`.  
   - Aceita comandos no console (`checksum`, `hook status/retry`, `vars ...`).  
   - Opcionalmente sobrescreve `domainAddress`/`tAddress` (POSEIDON), mostra console e grava logs de socket/arquivo.

2) `checksum_pipe_bridge.go` (bridge TCP -> pipes)  
   - Escuta TCP (padrão `0.0.0.0:2349`, configurável por env `CHECKSUM_BRIDGE_HOST`/`CHECKSUM_BRIDGE_PORT`).  
   - Recebe heartbeats do cliente via `\\.\pipe\checksum_control`, acompanha clientes ativos e mantém fila por cliente.  
   - Para cada requisição TCP: escolhe cliente ativo, escreve no pipe de requisição, lê a resposta do pipe de resposta e devolve ao plugin.  
   - Protocolo simples: payload|counter|seedHigh|seedLow → checksum|seedHigh|seedLow|counter (big-endian).

3) `plugin openkore/LatamChecksum.pl` (plugin OpenKore)  
   - Intercepta pacotes enviados ao servidor (xKore 0/3), habilita checksum após login no mapa ou primeiro pacote 0B1C.  
   - Conecta ao bridge (`ip_socket`/`port_socket` ou env `CHECKSUM_BRIDGE_HOST`/`CHECKSUM_BRIDGE_PORT`), envia payload+meta, recebe checksum e anexa 1 byte ao pacote.  
   - Opcional: loga checksums em `checksum_data.csv` (ativar com `checksum_csv_log 1`).  
   - Zera estado em desconexões.

Fluxo do checksum
-----------------
1. Plugin intercepta pacote, envia para o bridge TCP com `counter`, `seedHigh`, `seedLow`.  
2. Bridge escolhe um cliente (main.go) vivo pelo heartbeat e escreve no named pipe de requisição.  
3. DLL calcula seed/checksum usando funções nativas do jogo e devolve via pipe de resposta.  
4. Bridge retorna ao plugin, que adiciona o byte de checksum e libera o envio do pacote.

Configuração rápida
-------------------
Arquivo `xkore1_config.txt` (gerado se não existir) – valores padrão podem ser sobrescritos com `XKORE1_<NOME>`:
- Endereços (hex): `WIN32_SEND`, `WIN32_RECV`, `CHECKSUM`, `SEED`, `T_ADDRESS`, `DOMAIN_ADDRESS`.
- Flags: `POSEIDON` (injeção de endereço do servidor), `CHECKSUM_SERVER` (pipes ativos), `SHOW_CONSOLE`, `SAVE_LOG`, `SAVE_SOCKET_LOG`, `PAUSE_ON_ERROR`.

Plugin OpenKore (`control/config.txt`):
```
############ LatamChecksum ############
ip_socket    172.65.175.xx   # IP onde o bridge está escutando
port_socket  2349            # Porta do bridge
checksum_csv_log 0           # 1 para gerar checksum_data.csv
```

Build
-----
- DLL/ASI (cliente): `go build -buildmode=c-shared -o xkore1.asi src_xkore/main.go`
- Bridge: `go build -o checksum_pipe_bridge.exe checksum_pipe_bridge.go`
- (Opcional) Stress test: `go build -o stress_client.exe src_xkore/stress_client.go`

Diagnóstico rápido
------------------
- Console do cliente: comandos `checksum`, `hook status`, `hook retry`, `vars domain set`.  
- Logs: `xkore1_logs.txt` e `xkore1_socket_logs.txt` (se habilitados); plugin pode gerar `checksum_data.csv`.  
- Heartbeat/pipe: ver mensagens `[PIPE]` no console do cliente e `[CTRL]`/`[QUEUE]` no bridge.
