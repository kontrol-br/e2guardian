# Proxy-Basic: comportamento da resolução de grupos

Nos testes reportados, o e2guardian autenticou o usuário via plug-in `proxy-basic`, mas o filtro resultante caiu sempre no primeiro grupo configurado (ou no valor definido em `defaultfiltergroup`). A revisão do código confirma que:

- A função `auth_proxy_basic`, chamada pelo plug-in, apenas consulta a lista `defaultusermap` e encerra a avaliação se o usuário não estiver presente nela. Nenhum fallback consulta o `ipmap` ou outras listas. 【F:configs/preauth.story†L40-L57】
- O arquivo `proxy-basic.conf` explica que definir `defaultfiltergroup` garante que o plug-in sempre encontrará um grupo, mesmo se o usuário não estiver na lista de grupos. Isso reproduz o comportamento visto nos logs. 【F:configs/authplugins/proxy-basic.conf†L1-L23】

## Ajustes sugeridos

1. Duplicar a lógica sugerida nos comentários de `preauth.story`, acrescentando um fallback que consulte `ipmap` (ou outra lista apropriada) quando a busca em `defaultusermap` falhar.
2. Alternativamente, garantir que o usuário conste em `filtergroupslist`/`defaultusermap` para que o plug-in encontre o grupo correto sem recorrer ao fallback.

Os logs mencionados demonstram exatamente essa ausência de correspondência na lista de usuários: após a autenticação, o mecanismo não encontra entrada no `defaultusermap` e retorna imediatamente, fazendo com que a seleção de grupo caia nos valores padrão.
