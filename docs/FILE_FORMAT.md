# Teuzin Vault - Formato de arquivo

Status: proposta preliminar, ainda não implementada.
Versão proposta: 1
Extensão: .tvault
Autor: Matheus M. Diegues

## 1. Objetivo

Definir um formato de arquivo para armazenar arquivos e pastas
compactados e protegidos criptograficamente.

O formato deve permitir:
- Processamento incremental de arquivos grandes.
- Integridade e autenticidade dos dados.
- Detecção de adulteração, reordenação e truncamento.
- Desbloqueio por autenticador FIDO2.
- Recuperação independente do autenticador físico.

## 2. Algoritmos propostos

- Criptografia de dados: AES-256-GCM.
- Derivação de chaves: HKDF-SHA256.
- Compactação: Zstandard.
- Material HMAC-secret: extensão FIDO2 hmac-secret.
- Chaves de dados: aleatórias, com 256 bits.

## 3. Chave de dados

Cada arquivo .tvault terá uma DEK (Data Encryption Key)
aleatória de 256 bits.

A DEK será utilizada exclusivamente para proteger os dados
daquele arquivo.

A DEK nunca será armazenada em texto puro no contêiner.

## 4. Mecanismos de desbloqueio

O formato deverá admitir múltiplos mecanismos independentes
de proteção da mesma DEK.

### 4.1 Autenticador FIDO2

- Utilizar HMAC-secret.
- Respeitar o RP ID configurado para o projeto.
- Utilizar salt aleatório de 32 bytes.
- Derivar uma chave de proteção com HKDF-SHA256.
- Armazenar somente os metadados públicos necessários.
- Nunca armazenar PIN ou resultado HMAC-secret.

### 4.2 Recuperação independente

- Utilizar segredo aleatório de pelo menos 256 bits.
- Não depender da TrustKey.
- Derivar a chave de proteção usando HKDF-SHA256.
- Permitir recuperar a mesma DEK.
- Definir posteriormente um formato seguro e amigável para
  guardar e restaurar o material de recuperação.

## 5. Estrutura preliminar do contêiner

O contêiner deverá possuir:

1. Identificador mágico TVLT.
2. Versão do formato.
3. Comprimento do cabeçalho.
4. Cabeçalho JSON UTF-8 determinístico.
5. Registros de dados criptografados.
6. Registro final autenticado obrigatório.

O cabeçalho deverá ter limite de tamanho e validação rigorosa.
Chaves JSON duplicadas deverão ser rejeitadas.

Informações pessoais, caminhos originais e nomes de arquivos
não deverão ficar expostos no cabeçalho público.

## 6. Cabeçalho

O cabeçalho deverá identificar:

- Versão do formato.
- Algoritmos empregados.
- Identificador aleatório do contêiner.
- Tamanho dos blocos.
- Prefixo de nonce.
- Mecanismos de desbloqueio disponíveis.
- Metadados públicos necessários para cada mecanismo.

A representação exata deverá ser determinística.
Os bytes originais do cabeçalho serão autenticados como AAD.

Limite preliminar do cabeçalho: 64 KiB.

## 7. Criptografia por blocos

Configuração preliminar:

- Tamanho de bloco: 1 MiB.
- Cifra: AES-256-GCM.
- Nonce: prefixo aleatorio de 4 bytes por container + contador big-endian de 8 bytes (96 bits no total).
- Limite de registros de dados: 1.048.576 por container.
- Limite de dados compactados por registro: 1 MiB.
- Tag de autenticação: 16 bytes.
- Sequência iniciada em zero.
- Contadores nunca poderão ser reutilizados com a mesma DEK.

Cada registro deverá autenticar:
- Cabeçalho do contêiner.
- Tipo de registro.
- Índice sequencial.
- Comprimento do registro.
- Conteúdo criptografado.

O limite de registros deverá impedir o estouro do contador.

## 8. Registro final

Um registro final autenticado será obrigatório.

Ele deverá confirmar:
- Quantidade de blocos.
- Quantidade total de bytes compactados.
- Encerramento correto do fluxo.

O leitor deverá rejeitar arquivos sem registro final,
com registros adicionais ou com sequência inválida.

## 9. Compactação e descompactação

A compactação deverá acontecer antes da criptografia.

O fluxo Zstandard deverá ser processado incrementalmente,
sem exigir que todo o arquivo original fique em memória.

A descompactação deverá possuir limites explícitos de saída,
além de detectar fluxo incompleto e dados adicionais.

## 10. Proteção contra falhas

O formato e sua implementação deverão testar:

- Cabeçalhos inválidos.
- Cabeçalhos adulterados.
- Chaves incorretas.
- Nonces e tags inválidos.
- Blocos modificados.
- Blocos reordenados.
- Arquivos truncados.
- Registros extras.
- Fluxos compactados malformados.
- Limites de memória e tamanho.

A gravação de arquivos deverá utilizar arquivo temporário
e finalização atômica sempre que suportada pelo sistema.

## 11. Privacidade

Não deverão ser armazenados:
- PINs FIDO2.
- Segredos HMAC-secret.
- DEKs em texto puro.
- Chaves de proteção em texto puro.
- Tokens ou credenciais pessoais.

## 12. Estado de implementação

Esta especificação é preliminar.

Nenhuma compatibilidade com versões futuras está garantida.

O formato só poderá ser considerado estável após:
- Implementação completa.
- Testes de integridade e recuperação.
- Testes de arquivos grandes.
- Revisão independente de segurança.
- Definição de política de versionamento.