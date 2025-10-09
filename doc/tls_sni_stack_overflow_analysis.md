# TLS SNI stack overflow analysis

## Contexto
O `e2guardian` sofreu "core crash" e mensagens de `stack overflow detected` quando operava em modo de proxy transparente com interceptação SSL. O problema não se reproduzia com proxy declarado, indicando que estava ligado ao código que analisa o ClientHello TLS para obter o SNI.

## Comportamento antigo
A função `get_TLS_SNI` percorria o *ClientHello* manipulando ponteiros brutos. Ao localizar a extensão de Server Name Indication, ela escrevia um byte `\0` logo após o nome extraído para reutilizar o mesmo *buffer* como uma `char*` terminada em NUL:

```c++
*(curr + namelen) = (char)0;
return (char*)curr;
```

Entretanto, `curr` apontava para dentro do *ClientHello* recebido por `recv(MSG_PEEK)`. Esse *buffer* tinha o tamanho exato da mensagem enviada pelo cliente. Caso o nome SNI fosse posicionado perto do fim do pacote, `curr + namelen` apontava exatamente para o byte imediatamente após o *ClientHello*. Escrever o `\0` nessa posição resultava em escrita fora dos limites e corrompia a pilha (o *buffer* local que armazena os bytes do handshake). Isso explica os `stack overflow detected` do `libc` e os *core dumps* vistos no ambiente FreeBSD.

Além disso, vários cálculos de comprimento assumiam implicitamente que haveria bytes suficientes antes de cada acesso. Se o pacote fosse truncado ou se o cliente enviasse campos menores que o esperado, `*(unsigned short*)curr` e leituras subsequentes poderiam avançar `curr` além do final do *buffer* sem uma checagem de limites clara, favorecendo o mesmo tipo de corrupção.

## Correção aplicada
As alterações introduzidas:

1. **Validação estrita de limites** – cada passo da navegação dentro do *ClientHello* verifica se há bytes suficientes antes de ler ou avançar ponteiros. Caso contrário, a função retorna `NULL` sem tocar o *buffer*. Quando o pacote capturado é menor do que o tamanho total das extensões informado no ClientHello, o laço limita a busca ao que foi efetivamente recebido, evitando falsos negativos ao mesmo tempo em que impede leitura fora dos limites.
2. **Cópia para `thread_local std::string`** – em vez de escrever `\0` dentro do *buffer* espiado, o nome SNI é copiado para uma `std::string` específica da *thread*. O ponteiro retornado aponta para o conteúdo seguro dessa string, evitando qualquer escrita fora dos limites do *ClientHello* original.

Essa combinação elimina a gravação fora da pilha e garante que entradas malformadas não causem estouro de pilha, estabilizando o modo transparente com interceptação SSL.
