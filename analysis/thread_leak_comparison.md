# Comparativo de vazamento de threads entre v5.3.8 e v5.5

## Contexto
A base `work` está alinhada com o release 5.3.8_9 e mantém o pipeline de logging original (fila + `std::ofstream`) descrito em `FatController.cpp`. 【F:src/FatController.cpp†L126-L205】
A versão oficial 5.5.8r reorganizou o mesmo arquivo para usar o novo `Logger` centralizado e acrescentou flags atômicas para rotação e sincronização das threads de log.【F:analysis/FatController_v5.5_snippets.cpp†L6-L32】

## Diferenças relevantes

| Tema | v5.3.8 | v5.5 |
|------|--------|------|
| Estado global das threads de log | Usa `logger_ttg` e filas globais simples para encerrar os listeners, sem mecanismo dedicado de rotação. 【F:src/FatController.cpp†L126-L205】【F:src/FatController.cpp†L698-L772】 | Substitui `logger_ttg` por `e2logger_ttg` e adiciona `rotate_access/rotate_request/rotate_dstat`, consumidos pelo logger central para reabrir arquivos sem reiniciar threads. 【F:analysis/FatController_v5.5_snippets.cpp†L6-L32】【F:analysis/FatController_v5.5_snippets.cpp†L66-L76】 |
| Ordem de criação das threads | O master cria as threads de log (`log_listener` e `RQlog_listener`) **antes** de aplicar `pthread_sigmask`, fazendo com que os listeners herdem a máscara default e possam receber sinais que eram destinados apenas ao master. 【F:src/FatController.cpp†L1626-L1699】 | A máscara de sinais é aplicada no master **antes** de qualquer `std::thread`, garantindo que as threads derivadas nasçam com os sinais bloqueados e dependam apenas da fila/flags para coordenação. 【F:analysis/FatController_v5.5_snippets.cpp†L34-L55】 |
| Tratamento de `SIGUSR1` | `SIGUSR1` apenas marca `gentlereload`, o que provoca recarga de listas e recriação de objetos, mas não sinaliza explicitamente os threads de log/estatística. Isso faz com que eles fiquem aguardando no `pop()` sem consciência de eventos de rotação ou encerramento. 【F:src/FatController.cpp†L1746-L1826】 | `SIGUSR1` aciona as flags de rotação. Cada listener detecta o flag na próxima iteração, realiza `rotate()` no logger e limpa a flag, evitando reiniciar threads e prevenindo acúmulo de listeners órfãos. 【F:analysis/FatController_v5.5_snippets.cpp†L56-L76】 |
| Loop de log | O listener grava direto em `std::ofstream` e só sai quando `logger_ttg` é forçado e uma string vazia é inserida na fila. Não existe lógica para reabrir arquivos ou liberar recursos intermediários. 【F:src/FatController.cpp†L698-L772】【F:src/FatController.cpp†L1882-L1887】 | O listener consulta `rotate_*` a cada mensagem, delega a rotação ao `Logger` e continua trabalhando, evitando que chamadas recorrentes a `SIGUSR1` gerem novas threads. 【F:analysis/FatController_v5.5_snippets.cpp†L66-L76】 |

## Diagnóstico do vazamento observado na 5.3.8

O sintoma descrito (threads permanecendo ativas mesmo sem tráfego) coincide com situações em que o master recebe sinais fora de ordem:

* Como `pthread_sigmask` é aplicado **depois** da criação das threads, `SIGUSR1`/`SIGHUP` podem atingir diretamente `log_listener`/`RQlog_listener`. Esses sinais interrompem a espera no `pop()` sem que existam flags específicas para coordenar a recuperação; o resultado são threads que retornam ao loop sem dados válidos e permanecem bloqueadas indefinidamente, parecendo “vazar”. 【F:src/FatController.cpp†L1626-L1826】
* A ausência de flags de rotação faz com que o master injete apenas um `std::string` vazio ao desligar. Em cenários de rotação manual (kill `-USR1`) ou reinicializações parciais, o listener continua ativo e mantém o descritor de arquivo aberto, levando a contagem crescente de threads bloqueadas quando scripts externos decidem recriar o daemon para liberar os arquivos. 【F:src/FatController.cpp†L698-L772】【F:src/FatController.cpp†L1861-L1887】
* Em v5.5, o conjunto `rotate_*` atua como “sentinela” seguro: o master apenas seta a flag e o próprio thread de log resolve a rotação, sem necessidade de novos threads ou reinício do processo, eliminando o acúmulo observado. 【F:analysis/FatController_v5.5_snippets.cpp†L56-L76】

## Estratégia de backport

1. **Reordenar `pthread_sigmask`** – mover o bloco que inicializa `sigset_t` e chama `pthread_sigmask` para antes da criação dos threads de log/listener. Essa mudança é isolada, não depende do novo `Logger` e já mitiga sinais inesperados entrando nos listeners. 【F:src/FatController.cpp†L1626-L1679】
2. **Introduzir flags de rotação mínimas** – mesmo sem portar o `Logger` completo, é possível adicionar `std::atomic<bool>` para `rotate_access` e `rotate_request`, ajustar `log_listener` para observar essas flags e reabrir o `std::ofstream` local quando necessário. Esse passo exige alterações cuidadosas na porção antiga do logger, mas pode ser implementado sem tocar no restante do core.
3. **Manter compatibilidade** – preservar a API atual (funções, estruturas, opções) garante que `e2guardian.conf` e os scripts existentes continuem válidos. Recomenda-se encapsular as novas flags e a lógica de rotação atrás de condicionais para evitar dependência do `Logger` moderno.

Com esses dois primeiros passos, a 5.3.8 herda o comportamento que evita o acúmulo de threads, sem necessidade de migrar toda a pilha de logging da 5.5. O restante das otimizações (classe `Logger`, reorganização das estruturas `o.log`/`o.dstat`) só deve ser considerado caso se deseje alinhar completamente com a árvore 5.5, pois envolve mudanças extensas no parser de configuração e no build system.
