# Comparativo entre v5.5.8r e v5.3.8 (branch `work`)

## Melhorias já incorporadas na base 5.3.8
- **Flags atômicas para rotação dos logs** – a 5.3.8 já expõe `rotate_access`, `rotate_request` e `rotate_dstat`, consumindo-as nos listeners para reabrir arquivos apenas quando necessário. 【F:src/FatController.cpp†L126-L205】【F:src/FatController.cpp†L810-L838】
- **Ordem correta da máscara de sinais** – o master aplica `pthread_sigmask` antes de iniciar `log_listener` e `RQlog_listener`, impedindo que as threads filhas recebam sinais indevidos, assim como observado na série 5.5.【F:src/FatController.cpp†L1668-L1689】【F:analysis/FatController_v5.5_snippets.cpp†L34-L63】
- **Rotação dos dstat sem reinício** – `stat_rec::reset` fecha e reabre o `FILE*` quando `rotate_dstat` é sinalizado, o que elimina a necessidade de recriar threads durante `SIGUSR1`. 【F:src/FatController.cpp†L176-L230】【F:analysis/FatController_v5.5_snippets.cpp†L15-L32】

## Diferenças remanescentes
| Tema | v5.3.8 (`work`) | v5.5.8r | Impacto/Complexidade |
|------|-----------------|---------|----------------------|
| **Backend de logging** | Uso direto de `std::ofstream`/`syslog`, com fechamento manual de arquivos e sem camadas para UDP/STDOUT. 【F:src/FatController.cpp†L810-L838】 | Centralização via `Logger`, com macros `E2LOGGER_*`, flush dedicado e suporte a múltiplos destinos. 【F:analysis/FatController_v5.5_snippets.cpp†L15-L77】 | Alta – requer portar `Logger.*` e ajustar dezenas de chamadas; bom para roadmap, não para mudança rápida. |
| **Placeholders em branco no accesslog** | Sempre converte strings vazias em `"-"`, independentemente da preferência do operador. 【F:src/FatController.cpp†L840-L918】 | Configura `use_dash_for_blanks` e permite preservar campos vazios reais. 【F:analysis/FatController_v5.5_snippets.cpp†L81-L94】 | Baixa – basta acrescentar um `bool` no `OptionContainer`, ler a nova opção e ajustar o branch que formata `logline`. |
| **Proxy transparente e IP original** | Conexões diretas dependem exclusivamente de `cm.urldomain` ou de um `getsockopt` protegido por `ENABLE_ORIG_IP`, que apenas valida o host header e não reutiliza o IP original ao reconectar. 【F:src/ConnectionHandler.cpp†L460-L557】【F:src/ConnectionHandler.cpp†L953-L1018】 | Introduz a flag `useoriginalip` e, quando ativa, reutiliza `checkme.orig_ip`/`orig_port` obtidos via `SO_ORIGINAL_DST`, inclusive desconsiderando IPs pertencentes ao próprio proxy para evitar loops. 【F:analysis/ConnectionHandler_v5.5_useoriginalip.cpp†L1-L39】 | Média – exige portar a flag, extrair uma rotina `get_original_ip_port()` e ajustá-la para compilar fora do `#ifdef ENABLE_ORIG_IP`. |
| **PID file antes da daemonização** | Escreve o PID apenas após o `daemonise`, o que dificulta supervisores que esperam o PID do master imediatamente. 【F:src/FatController.cpp†L1669-L1675】【F:src/SysV.cpp†L183-L197】 | Chama `sysv_writepidfile(pidfilefd, 0)` antes de soltar o terminal e trata erro via `Logger`. 【F:analysis/FatController_v5.5_snippets.cpp†L96-L102】 | Baixa – adaptar `sysv_writepidfile` para aceitar um PID opcional (default `getpid()`) e realizar a chamada extra. |
| **Eco no console durante `--no-daemon`** | Logs iniciais dependem exclusivamente do syslog; quem roda em foreground não vê mensagens até o daemon anexar ao syslog. 【F:src/FatController.cpp†L1670-L1678】 | `Logger` escreve simultaneamente em `stderr` enquanto `g_is_starting` for verdadeiro. 【F:analysis/FatController_v5.5_snippets.cpp†L96-L102】 | Média – precisa de um guardião semelhante (`g_is_starting`) e chamadas extras a `std::cerr` ou uma versão simplificada do `Logger`. |

## Recomendações imediatas (baixo esforço)
1. **Adicionar suporte a `usedashforblank`**
   - Declarar `bool use_dash_for_blanks = true;` no `OptionContainer`, ler a opção no parser e ajustar o bloco do `log_listener` que normaliza cada `logline` para respeitar a configuração.【F:src/FatController.cpp†L840-L918】【F:analysis/FatController_v5.5_snippets.cpp†L81-L94】
   - Benefício: compatibilidade com setups que exigem colunas vazias em formato CSV, além de paridade funcional com 5.5.

2. **Atualizar `sysv_writepidfile` para aceitar PID explícito**
   - Alterar a assinatura para `int sysv_writepidfile(int pidfilefd, pid_t pid = 0)` e usar `pid == 0 ? getpid() : pid` internamente, mantendo compatibilidade com chamadas existentes.【F:src/SysV.cpp†L183-L197】
   - Invocar a função antes e depois da daemonização, replicando o padrão da 5.5 para que scripts `systemd` ou `rc` consigam identificar o processo master de imediato.【F:analysis/FatController_v5.5_snippets.cpp†L96-L102】

## Itens para roadmap (maior esforço)
- **Portar o `Logger` completo** para liberar destinos múltiplos (UDP/STDOUT), formatação flexível e mecanismos de flush centralizados. Isso envolve introduzir `Logger.cpp/.hpp`, substituir `syslog` por macros `E2LOGGER_*` e ajustar a estrutura de opções (`o.log.*`).【F:analysis/FatController_v5.5_snippets.cpp†L15-L77】
- **Rever o pipeline de stats** para eliminar o uso direto de `FILE*`, passando a reutilizar o `Logger` também para `dstats`, o que uniformiza a rotação e simplifica o código.【F:analysis/FatController_v5.5_snippets.cpp†L15-L32】

## Correção de 127.0.0.1 no proxy transparente

Os relatos de múltiplos bloqueios aparentes para `127.0.0.1` decorrem de implantações transparentes onde o e2guardian reconecta-se ao próprio IP local ao invés do destino original. A série 5.5 introduziu a opção `useoriginalip` justamente para direcionar HTTP/HTTPS transparentes ao IP/porta capturados via `SO_ORIGINAL_DST`, solução destacada tanto no `ChangeLog` quanto no comentário do `e2guardian.conf`.【F:analysis/ChangeLog_v5.5_useoriginalip.txt†L1-L1】【F:analysis/e2guardian.conf_v5.5_useoriginalip.txt†L1-L9】 O trecho portado acima mostra que, quando a flag está ligada, o `connectUpstream` reutiliza `cm.orig_ip` e ignora IPs pertencentes ao próprio appliance, evitando que logs apontem para `127.0.0.1`.【F:analysis/ConnectionHandler_v5.5_useoriginalip.cpp†L1-L35】

Na base 5.3.8 o caminho direto continua preso ao `cm.urldomain` e o bloco protegido por `ENABLE_ORIG_IP` apenas valida o host header, sem alterar o destino do `connect()` subsequente, o que explica a recorrência dos registros em `127.0.0.1` quando não há `Host:`/SNI válidos.【F:src/ConnectionHandler.cpp†L460-L557】【F:src/ConnectionHandler.cpp†L953-L1018】 Portar a melhoria requer três passos de baixo impacto:

1. **Adicionar a flag de configuração.** Estender o parser para aceitar `useoriginalip` lado a lado de `logconnectionhandlingerrors`, armazenando em um novo `bool` (`use_original_ip_port`).【F:src/OptionContainer.cpp†L699-L736】
2. **Extrair `get_original_ip_port()`.** Reaproveitar o bloco atual que chama `getsockopt(SO_ORIGINAL_DST)` para popular `checkme.orig_ip`/`orig_port`, removendo o `#ifdef ENABLE_ORIG_IP` e encapsulando numa função reutilizável, seguindo o padrão da 5.5.【F:src/ConnectionHandler.cpp†L953-L1018】【F:analysis/ConnectionHandler_v5.5_useoriginalip.cpp†L19-L35】
3. **Usar o IP original no `connectUpstream`.** Reutilizar `cm.orig_ip` quando a flag estiver ativa e quando o proxy estiver em modo direto, espelhando a condição da 5.5, para que as tentativas sejam encaminhadas ao destino interceptado em vez de `127.0.0.1`.【F:src/ConnectionHandler.cpp†L460-L516】【F:analysis/ConnectionHandler_v5.5_useoriginalip.cpp†L1-L17】

Com essas adaptações o branch 5.3.8 passa a reproduzir o comportamento da série 5.5 sem renomear arquivos nem alterar a árvore de diretórios, resolvendo o ruído de bloqueios direcionados ao loopback e melhorando compatibilidade com aplicativos que omitem o host/SNI.
