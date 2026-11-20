# Política de segurança

O Teuzin Vault está em desenvolvimento. Ainda não é considerado adequado para proteger dados de produção.

## Comunicação de vulnerabilidades

Não publique detalhes de vulnerabilidades, segredos ou arquivos protegidos em issues públicas.

Entre em contato com o mantenedor por um canal privado antes de divulgar uma vulnerabilidade.

## Princípios de segurança

- Nunca armazenar PIN ou segredo HMAC-secret em arquivos.
- Nunca reutilizar nonces de AES-GCM com a mesma chave.
- Usar chaves aleatórias e derivação criptográfica apropriada.
- Autenticar os metadados do formato de arquivo.
- Projetar recuperação independente do autenticador físico.
- Testar integridade e recuperação antes de considerar o formato estável.

## Aviso

Não use versões experimentais para armazenar a única cópia de arquivos importantes.
