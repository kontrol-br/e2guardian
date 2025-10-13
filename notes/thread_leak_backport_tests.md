# Plano de testes para o backport do controle de threads

Este plano resume verificações recomendadas após aplicar ao branch 5.3.8 as correções de controle de threads inspiradas na série 5.5.

## 1. Testes automatizados básicos
1. **Compilação completa**: execute `./configure && make -j$(nproc)` para garantir que as alterações não quebram o build.
2. **Testes unitários existentes**: rode `make check` para validar o conjunto atual de testes.

## 2. Testes funcionais de rotação de logs
1. Inicie o serviço com o binário recompilado e gere tráfego controlado (por exemplo, usando `curl` ou `ab`).
2. Envie `SIGUSR1` para o processo principal e confirme:
   - Reabertura correta dos arquivos de log (`requests`, `events`, `dstats`).
   - Ausência de threads órfãs via `ps -L` ou `top -H`.
3. Repita o sinal múltiplas vezes para garantir estabilidade.

## 3. Testes de carga prolongada
1. Gere tráfego contínuo por pelo menos 12 horas com uma ferramenta como `httperf` ou `siege`.
2. Monitore uso de memória e contagem de threads com `pidstat -t 60` ou `systemd-cgtop` para garantir ausência de crescimento descontrolado.

## 4. Testes de regressão de funcionalidades
1. Valide políticas de filtragem existentes (listas de bloqueio/permite, autenticação, categorias).
2. Confirme integração com `pfSense` e scripts de rotação externa, se usados.

## 5. Observabilidade
1. Verifique logs de eventos para mensagens de erro relacionadas a falhas em `pthread`.
2. Utilize `valgrind --tool=helgrind` ou `drd` em um ambiente de staging para detectar condições de corrida adicionais.

Seguir estas etapas ajuda a assegurar que a correção de vazamento de threads não introduz regressões nem compromete a estabilidade da versão 5.3.8.
