# Análise de vazamento de threads: comparação v5.3.8 vs. v5.5

## Visão geral das diferenças
- A árvore `v5.5` introduz uma camada de logging centralizada (`src/Logger.cpp`/`Logger.hpp`) que substitui o fluxo de logs direto usado na série 5.3.x. Isso adiciona filas dedicadas para rotação, flags atômicas extras (`rotate_access`, `rotate_request`, `rotate_dstat`) e simplifica o encerramento das threads de log.
- O commit `7865bf6840dd216e68683fe443cdafb99554dbc4` (registrado na `ChangeLog` oficial como "Fix #815") move a chamada a `pthread_sigmask` para antes da criação de **qualquer** thread. Na v5.3.8 a máscara só era ajustada após os `http_worker`/`listen` threads já estarem ativos, permitindo que sinais assíncronos atingissem as threads filhas e as deixassem presas em estados inconsistentes.
- `stat_rec::start` ganha um parâmetro `bool firsttime` para evitar reinicializações em momentos errados quando há rotação de logs, complementando o novo logger. Esse ajuste não é necessário para corrigir o vazamento, mas faz parte do conjunto de mudanças da 5.5.

## Origem provável do vazamento de threads
- Em ambientes de alta permanência (pfSense + MITM), sinais como `SIGUSR1`/`SIGHUP` são usados para rotação e recarga. Na 5.3.8 os workers já estavam em execução quando o `pthread_sigmask` era aplicado, então cada worker poderia capturar o sinal e não repassá-lo ao thread mestre, mantendo filas e contadores internos (`busychildren`) permanentemente inflados.
- A alteração de 5.5 garante que os workers herdem a máscara de sinais correta: os sinais são bloqueados **antes** do `std::thread` iniciar, e somente o master executa `sigtimedwait`. Isso elimina a condição na qual threads permanecem vivas mesmo após o tráfego cessar ou após tentativas de reload.

## Backport seguro para v5.3.8
- Para aproveitar o fix sem trazer toda a pilha de logging da 5.5 basta reposicionar o bloco que constrói `sigset_t`/`pthread_sigmask` para antes da criação das threads de worker e listener. O comportamento do restante do código permanece compatível com as estruturas antigas (`Queue`, `logger_ttg`, etc.).
- Adicionalmente pode-se manter um comentário explicando a origem do ajuste (commit #815) para facilitar auditorias futuras e evitar regressões durante merges locais.
- Não há dependências diretas com o novo `Logger`, portanto o risco de quebrar funcionalidades existentes na 5.3.8 é mínimo. O ajuste foi aplicado no `FatController.cpp` desta árvore seguindo a mesma lógica da 5.5.

## Recomendações operacionais
1. Validar em ambiente de homologação executando ciclos de `SIGHUP`/`SIGUSR1` para confirmar que os workers permanecem estáveis e que os contadores `busychildren` retornam a zero quando o tráfego cessa.
2. Monitorar o consumo de threads via `dstats.log` ou `ps -L` após o deploy para confirmar a eliminação do vazamento crônico observado na 5.3.8.
3. Planejar uma migração gradual para o subsistema de logging da 5.5 apenas se houver necessidade de recursos adicionais (como rotação integrada); ele não é requisito para resolver o vazamento.
