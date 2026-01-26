# Captura de core dump no FreeBSD/pfSense

> Objetivo: habilitar core dumps para diagnosticar falhas (ex.: processos saindo com sinal 4).

## 1) Verificar status atual

```sh
sysctl kern.coredump
sysctl kern.corefile
sysctl kern.sugid_coredump
```

## 2) Ativar core dumps (sessão atual)

```sh
sysctl kern.coredump=1
sysctl kern.corefile=/var/coredumps/%N.%P.core
```

> `%N` = nome do binário, `%P` = PID.

Se o processo for setuid/setgid, habilite também:

```sh
sysctl kern.sugid_coredump=1
```

## 3) Persistir as mudanças

Em FreeBSD/pfSense, adicione em `/etc/sysctl.conf`:

```
kern.coredump=1
kern.corefile=/var/coredumps/%N.%P.core
kern.sugid_coredump=1
```

> Ajuste `kern.sugid_coredump` somente se for necessário. Em ambientes de produção
> pode haver restrições de segurança.

## 4) Garantir diretório de destino e permissões

```sh
mkdir -p /var/coredumps
chmod 1777 /var/coredumps
```

## 5) Remover limites de core dump (ulimit)

Verifique o limite atual:

```sh
ulimit -c
```

Para permitir core dumps na sessão atual:

```sh
ulimit -c unlimited
```

Para serviços iniciados via rc, use um wrapper de serviço ou ajuste a classe de
login apropriada para o usuário do daemon, garantindo `coredumpsize=unlimited`.

## 6) Validar geração do core

Forçar um core (em um processo de teste) ajuda a validar o fluxo. Por exemplo:

```sh
kill -ABRT <PID>
```

Se tudo estiver correto, um arquivo deve aparecer em `/var/coredumps/`.

## 7) Capturar core do e2guardian em execução

Com o e2guardian rodando (ex.: `/usr/local/sbin/e2guardian`), você pode gerar
um core manualmente após confirmar que os ajustes acima estão ativos:

```sh
ps -axu | grep e2guardian
kill -ABRT <PID_DO_E2GUARDIAN>
```

> Observação: o processo vai encerrar com sinal e o core será gravado em
> `/var/coredumps/` se `ulimit -c` e os `sysctl` estiverem corretos.

## 8) Localizar e analisar o core

```sh
ls -lh /var/coredumps/
```

Depois, use `gdb`/`lldb` com o binário e o core para obter backtrace.
