# Sugestão de build com símbolos de debug (pfSense/FreeBSD port)

Abaixo está uma sugestão de ajuste no Makefile do port para gerar binários com
símbolos de debug quando a opção `DEBUG` estiver habilitada.

## 1) Adicionar flags de debug (C/C++)

```make
DEBUG_CFLAGS=   -g -O0 -fno-omit-frame-pointer
DEBUG_CXXFLAGS= -g -O0 -fno-omit-frame-pointer
```

Essas flags geram símbolos (`-g`) e evitam otimizações que dificultam o backtrace.

## 2) Evitar stripping do binário em modo debug

Para manter os símbolos no binário, desabilite o `strip` quando `DEBUG` estiver
ativo. Em ports, isso pode ser feito ao adicionar:

```make
DEBUG_VARS= STRIP=
```

Evite usar `.if ${PORT_OPTIONS:MDEBUG}` antes de incluir
`bsd.port.options.mk`, pois `PORT_OPTIONS` ainda não existe durante `make config`.

## 3) Exemplo de bloco completo

```make
OPTIONS_DEFINE=  CLISCAN ICAP NTLM DNS EMAIL DEBUG DOCS SSL_MITM

DEBUG_CONFIGURE_OFF=     --with-dgdebug=off --with-newdebug=off
DEBUG_CONFIGURE_ON=      --with-dgdebug=on --with-newdebug=on
DEBUG_CFLAGS=            -g -O0 -fno-omit-frame-pointer
DEBUG_CXXFLAGS=          -g -O0 -fno-omit-frame-pointer
DEBUG_VARS=              STRIP=
```

Depois disso, compile o port com a opção `DEBUG` habilitada para que o
`/usr/local/sbin/e2guardian` tenha símbolos e o GDB consiga resolver as funções.
