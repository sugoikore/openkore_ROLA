================================================================================
                    XKORE1 CHECKSUM SYSTEM - DOCUMENTAÇÃO
================================================================================

VISÃO GERAL
-----------
Este sistema implementa um checksum dinâmico para servidores Ragnarok Online
que utilizam proteção checksum. Inclui:
  - Plugin Perl (LatamChecksum.pl) para OpenKore
  - Servidor TCP checksum em Go (main.go)
  - Cliente de stress test (stress_client.go)
  - Sistema de logging CSV para análise de pacotes

================================================================================
ARQUIVOS DO SISTEMA
================================================================================

1. LatamChecksum.pl
   - Plugin OpenKore que intercepta pacotes e adiciona checksum
   - Comunica-se com o servidor TCP checksum (main.go)
   - Opcional: registra dados de checksum em CSV

2. main.go
   - Servidor TCP checksum (compila para xkore1.asi/dll)
   - Injeta hooks no cliente RO
   - Calcula checksums usando funções nativas do cliente
   - Opcionalmente injeta configurações POSEIDON

3. stress_client.go
   - Cliente de teste para validar servidor checksum
   - Modo random: gera pacotes aleatórios
   - Modo replay: reproduz pacotes do CSV

4. xkore1_config.txt
   - Arquivo de configuração principal (criado automaticamente)

================================================================================
CONFIGURAÇÃO - xkore1_config.txt
================================================================================

O arquivo xkore1_config.txt contém todas as configurações necessárias.
Será criado automaticamente com valores padrão na primeira execução.

PARÂMETROS DISPONÍVEIS:
-----------------------

# Endereços de memória (hexadecimal, sem 0x)
WIN32_SEND=14F550C              # Endereço da função send no cliente
WIN32_RECV=14F5510              # Endereço da função recv no cliente
CHECKSUM=518D30                 # Endereço da função checksum
SEED=518F10                     # Endereço da função de geração de seed
T_ADDRESS=14CAE00               # Endereço da string tAddress
DOMAIN_ADDRESS=11514A8          # Endereço do ponteiro domainAddress

# Configurações do servidor TCP checksum
CHECKSUM_SERVER_PORT=2349       # Porta TCP para servidor checksum

# Recursos opcionais (0=desligado, 1=ligado)
POSEIDON=1                      # Ativa/desativa injeção de tAddress/domainAddress
                                # 1 = Ativa (padrão)
                                # 0 = Desativa injeção automática

CHECKSUM_SERVER=1               # Ativa/desativa servidor TCP checksum
                                # 1 = Ativa servidor (padrão)
                                # 0 = Desativa servidor TCP

# Logging e debug
SHOW_CONSOLE=1                  # Mostra console de debug
SAVE_LOG=1                      # Salva logs em xkore1_logs.txt
SAVE_SOCKET_LOG=1               # Salva tráfego de rede em xkore1_socket_logs.txt

CONFIGURAÇÃO - LatamChecksum.pl (OpenKore)
IMPORTANTE: Após modificar xkore1_config.txt, reinicie o cliente RO.

VARIÁVEIS DE AMBIENTE (Overrides):
-----------------------------------
Você pode sobrescrever QUALQUER configuração usando variáveis de ambiente.
Basta adicionar o prefixo "XKORE1_" ao nome da configuração.

Exemplos no Windows CMD:
  set XKORE1_SHOW_CONSOLE=0
  set XKORE1_CHECKSUM=518D40
  set XKORE1_POSEIDON=0

Exemplos no Windows PowerShell:
  $env:XKORE1_SHOW_CONSOLE="0"
  $env:XKORE1_CHECKSUM="518D40"
  $env:XKORE1_POSEIDON="0"

Valores suportados via variável de ambiente:
  - WIN32_SEND (hex sem 0x)
  - WIN32_RECV (hex sem 0x)
  - CHECKSUM (hex sem 0x)
  - SEED (hex sem 0x)
  - T_ADDRESS (hex sem 0x)
  - DOMAIN_ADDRESS (hex sem 0x)
  - CHECKSUM_SERVER_PORT (decimal)
  - POSEIDON (0 ou 1)
  - CHECKSUM_SERVER (0 ou 1)
  - SHOW_CONSOLE (0 ou 1)
  - SAVE_LOG (0 ou 1)
  - SAVE_SOCKET_LOG (0 ou 1)

ORDEM DE PRIORIDADE:
  1. Variáveis de ambiente (maior prioridade)
  2. Valores em xkore1_config.txt
  3. Valores padrão hard-coded

USO PRÁTICO:
  - Teste diferentes endereços sem editar arquivo
  - Desative console/logs temporariamente
  - Útil para scripts de automação
  - Múltiplas configurações em testes

CONFIGURAÇÃO - LatamChecksum.pl (OpenKore)
================================================================================
CONFIGURAÇÃO - LatamChecksum.pl (OpenKore)
================================================================================

INSTALAÇÃO:
-----------
1. Copie LatamChecksum.pl para a pasta plugins/ do OpenKore
2. Adicione ao config.txt do OpenKore:

   # Configurações do LatamChecksum
   ip_socket 172.65.175.XX        # IP do servidor checksum (seu IP local)
   port_socket 2349               # Porta do servidor checksum
   checksum_csv_log 0             # CSV logging (0=desligado, 1=ligado)

PARÂMETROS:
-----------

ip_socket (obrigatório)
   - Endereço IP do servidor checksum (main.go/xkore1.asi)
   - Use o IP local da máquina onde o cliente RO está rodando
   - Normalmente 172.65.175.XX (onde XX é o último octeto)
   - Padrão: 172.65.175.33

port_socket (obrigatório)
   - Porta TCP do servidor checksum
   - Deve corresponder a CHECKSUM_SERVER_PORT em xkore1_config.txt
   - Padrão: 2349

checksum_csv_log (opcional)
   - Controla o registro de dados em CSV
   - 0 = Desligado (padrão) - sem logging
   - 1 = Ligado - cria checksum_data.csv

LOGGING CSV:
------------
Quando checksum_csv_log=1, o plugin cria checksum_data.csv com:
   - timestamp: Unix timestamp da requisição
   - counter: Valor do contador do pacote
   - seed_high: 32 bits altos da seed
   - seed_low: 32 bits baixos da seed
   - packet_hex: Dados do pacote em hexadecimal
   - packet_length: Tamanho do pacote
   - checksum: Valor do checksum recebido

USO: Este CSV pode ser usado com stress_client.go --replay para testes.

================================================================================
COMPILAÇÃO
================================================================================

MAIN.GO (Servidor checksum ASI/DLL):
------------------------------------
# Compilar como DLL (para usar com ASI Loader)
go build -buildmode=c-shared -o xkore1.asi main.go

STRESS_CLIENT.GO (Cliente de teste):
------------------------------------
# Compilar executável
go build -o stress_client.exe stress_client.go

REQUISITOS:
-----------
- Go 1.18 ou superior
- Windows (para main.go)
- CGO habilitado (padrão no Windows)

================================================================================
USO - STRESS_CLIENT.GO
================================================================================

O stress_client.go possui dois modos de operação:

MODO RANDOM (Padrão):
---------------------
Gera pacotes aleatórios para testar o servidor checksum.

Uso:
  stress_client.exe [opções]

Opções:
  --host string
      Endereço do servidor checksum (padrão: 127.0.0.1)
  
  --port int
      Porta do servidor checksum (padrão: 2349)
  
  --min int
      Mínimo de requisições por segundo (padrão: 1)
  
  --max int
      Máximo de requisições por segundo (padrão: 15)
  
  --min-bytes int
      Tamanho mínimo do payload em bytes (padrão: 5)
  
  --max-bytes int
      Tamanho máximo do payload em bytes (padrão: 80)
  
  --timeout duration
      Timeout do socket (padrão: 1s)

Exemplo:
  stress_client.exe --host 172.65.175.70 --port 2349 --min 5 --max 20

MODO REPLAY:
------------
Reproduz pacotes gravados no CSV gerado pelo LatamChecksum.pl

Uso:
  stress_client.exe --replay --csv checksum_data.csv [opções]

Opções adicionais:
  --replay
      Ativa modo replay (obrigatório)
  
  --csv string
      Caminho do arquivo CSV (padrão: checksum_data.csv)

O modo replay:
  - Carrega todos os registros do CSV
  - Seleciona aleatoriamente registros e envia ao servidor
  - Verifica se o checksum recebido corresponde ao esperado
  - Reporta discrepâncias (útil para debugging)
  - Roda indefinidamente até ser interrompido (Ctrl+C)

Exemplo:
  stress_client.exe --replay --csv checksum_data.csv --host 172.65.175.70

ESTATÍSTICAS EXIBIDAS:
----------------------
Ambos os modos exibem:
  - sent: Total de requisições enviadas
  - success: Requisições bem-sucedidas
  - failed: Requisições que falharam
  - mismatch: (somente replay) Checksums incompatíveis

================================================================================
FLUXO DE OPERAÇÃO
================================================================================

1. INICIALIZAÇÃO:
   a) Cliente RO carrega xkore1.asi (main.go compilado)
   b) ASI lê xkore1_config.txt
   c) Se CHECKSUM_SERVER=1: Inicia servidor TCP na porta especificada
   d) Se POSEIDON=1: Injeta tAddress e domainAddress automaticamente
   e) Aplica hooks nas funções send/recv do cliente

2. EXECUÇÃO DO OPENKORE:
   a) OpenKore carrega LatamChecksum.pl
   b) Plugin conecta ao servidor TCP checksum
   c) Para cada pacote enviado:
      - Remove checksum incorreto (se existir)
      - Envia pacote + metadados ao servidor TCP
      - Recebe checksum correto
      - Adiciona checksum ao pacote
      - Opcionalmente registra em CSV

3. PROCESSAMENTO NO SERVIDOR (main.go):
   a) Recebe: payload + counter + seed
   b) Determina tipo de pacote (seed/checksum)
   c) Chama função nativa apropriada do cliente
   d) Retorna: checksum + seed atualizada

4. ANÁLISE E TESTES:
   a) Habilitar checksum_csv_log=1 para coletar dados
   b) Jogar normalmente para acumular pacotes variados
   c) Usar stress_client.exe --replay para validar
   d) Verificar logs para diagnosticar problemas

================================================================================
TROUBLESHOOTING
================================================================================

PROBLEMA: "Failed to connect to checksum server"
SOLUÇÃO:
  - Verifique se xkore1.asi está carregado no cliente RO
  - Confirme CHECKSUM_SERVER=1 em xkore1_config.txt
  - Verifique ip_socket no config.txt do OpenKore
  - Use o IP correto (veja logs do console do cliente)

PROBLEMA: Checksums incorretos / desconexões
SOLUÇÃO:
  - Verifique endereços de memória em xkore1_config.txt
  - Confirme versão do cliente RO compatível
  - Ative SAVE_LOG=1 e analise xkore1_logs.txt
  - Use stress_client.exe para validar servidor

PROBLEMA: POSEIDON não funciona
SOLUÇÃO:
  - Verifique POSEIDON=1 em xkore1_config.txt
  - Confirme T_ADDRESS e DOMAIN_ADDRESS corretos
  - Reinicie o cliente RO após mudanças
  - Veja logs do console para mensagens de erro

PROBLEMA: CSV vazio ou não é criado
SOLUÇÃO:
  - Confirme checksum_csv_log=1 no config.txt do OpenKore
  - Verifique permissões de escrita na pasta
  - Jogue até enviar primeiro pacote (para inicializar)
  - Arquivo é criado somente após primeiro checksum

PROBLEMA: stress_client.exe reporta muitos mismatches
SOLUÇÃO:
  - CSV pode conter checksums de diferentes sessões
  - Seeds podem ter mudado entre gravações
  - Use dados de uma única sessão contínua
  - Limpe checksum_data.csv e colete novos dados

================================================================================
COMANDOS DO CONSOLE (main.go)
================================================================================

Quando SHOW_CONSOLE=1, o ASI abre um console com comandos interativos:

help ou ?
   - Lista todos os comandos disponíveis

checksum <seed> <counter> <hex1>[,<hex2>...]
   - Calcula checksum manualmente para pacotes
   - seed: valor da seed em hexadecimal (ex: 0x1234567890ABCDEF)
   - counter: valor do contador (0-4095)
   - hex: pacote(s) em hexadecimal (separados por vírgula)
   
   Exemplo:
     checksum 0x1234567890ABCDEF 0 1C0B
     checksum 0xABCDEF 5 1C0B,0123456789

hook status
   - Mostra status dos hooks SEND/RECV
   - Indica se estão ativos e endereços

hook retry
   - Tenta reaplicar os hooks SEND/RECV
   - Use se hooks falharem na inicialização

vars
   - Mostra valores de tAddress e domainAddress

vars t
   - Mostra apenas tAddress

vars domain
   - Mostra apenas domainAddress

vars domain set
   - Força atualização de domainAddress com IP fake

================================================================================
ARQUIVOS DE LOG
================================================================================

xkore1_logs.txt (SAVE_LOG=1)
   - Log geral do ASI
   - Inicialização, hooks, operações
   - Útil para debugging

xkore1_socket_logs.txt (SAVE_SOCKET_LOG=1)
   - Tráfego de rede completo
   - Todos os pacotes SEND/RECV
   - Formato: [timestamp] direção len dados_hex

checksum_data.csv (checksum_csv_log=1)
   - Dados de checksum para análise
   - Usado pelo stress_client.exe --replay
   - Formato CSV padrão

NOTA: Logs podem crescer rapidamente. Limpe periodicamente.

================================================================================
DICAS E MELHORES PRÁTICAS
================================================================================

1. COLETA DE DADOS:
   - Ative CSV logging apenas quando necessário
   - Colete durante uma sessão contínua de jogo
   - Inclua variedade de ações (movimento, ataque, skills)
   - Mais dados = melhor análise

2. TESTES:
   - Use stress_client.exe em modo random primeiro
   - Valide estabilidade do servidor checksum
   - Depois use modo replay com dados reais
   - Monitore mismatches para problemas

3. PERFORMANCE:
   - SAVE_SOCKET_LOG=0 para melhor performance
   - Checksum CSV adiciona overhead mínimo
   - Stress test ajuste --min/--max conforme necessário

4. SEGURANÇA:
   - Não compartilhe arquivos CSV (contêm dados da sessão)
   - Logs podem conter informações sensíveis
   - Limpe logs antigos regularmente

5. DEBUGGING:
   - Sempre ative SHOW_CONSOLE=1 durante setup
   - Use hook status para verificar inicialização
   - Analise logs para mensagens de erro
   - Teste com stress_client.exe antes de jogar

================================================================================
EXEMPLO DE CONFIGURAÇÃO COMPLETA
================================================================================

ArquivO: xkore1_config.txt
---------------------------
WIN32_SEND=14F550C
WIN32_RECV=14F5510
CHECKSUM=518D30
SEED=518F10
T_ADDRESS=14CAE00
DOMAIN_ADDRESS=11514A8
CHECKSUM_SERVER_PORT=2349
POSEIDON=1
CHECKSUM_SERVER=1
SHOW_CONSOLE=1
SAVE_LOG=1
SAVE_SOCKET_LOG=0

Arquivo: config.txt (OpenKore)
-------------------------------
# ... outras configs ...
ip_socket 172.65.175.70
port_socket 2349
checksum_csv_log 0

Comandos:
---------
# Compilar ASI
go build -buildmode=c-shared -o xkore1.asi main.go

# Compilar stress client
go build -o stress_client.exe stress_client.go

# Testar servidor (modo random)
stress_client.exe --host 172.65.175.70 --port 2349

# Depois de coletar CSV, testar replay
stress_client.exe --replay --csv checksum_data.csv --host 172.65.175.70

================================================================================
SUPORTE E CONTRIBUIÇÕES
================================================================================

Para reportar bugs ou sugerir melhorias:
  - Inclua versão do cliente RO
  - Anexe logs relevantes
  - Descreva passos para reproduzir
  - Mencione configurações usadas

================================================================================
                          FIM DA DOCUMENTAÇÃO
================================================================================
