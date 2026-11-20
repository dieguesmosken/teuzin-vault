# Teuzin Vault - Desenho técnico do formato V1

Status: proposta técnica, sujeita a revisão.
Autor: Matheus M. Diegues

## 1. Estrutura física

O arquivo será composto por:

1. Prefixo fixo.
2. Cabeçalho principal.
3. Registros de proteção da DEK.
4. Registros de dados.
5. Registro final autenticado.

Todos os inteiros binários utilizarão big-endian.

## 2. Prefixo fixo

| Campo | Tamanho |
|---|---:|
| Magic TVLT | 4 bytes |
| Versão | 2 bytes |
| Comprimento do cabeçalho | 4 bytes |

O comprimento máximo do cabeçalho será 64 KiB.

Versões desconhecidas serão rejeitadas.

## 3. Cabeçalho principal

O cabeçalho será JSON UTF-8 determinístico.

Regras:
- Chaves ordenadas.
- Sem espaços desnecessários.
- Sem chaves duplicadas.
- Sem campos desconhecidos na versão 1.
- Limite de 64 KiB.
- Validação rigorosa dos tipos e tamanhos.

O cabeçalho conterá:
- Identificador aleatório do contêiner.
- Algoritmos e suas versões.
- Tamanho máximo dos blocos.
- Prefixo de nonce.
- Identificadores dos mecanismos de desbloqueio.
- Metadados públicos necessários para cada mecanismo.

Nomes originais, caminhos e conteúdo dos arquivos não ficarão
expostos no cabeçalho.

O digest SHA-256 será calculado sobre o prefixo fixo e os bytes
exatos do cabeçalho.

Esse digest será utilizado na autenticação dos registros.

## 4. Proteção da DEK

Cada contêiner terá uma DEK aleatória de 32 bytes.

A DEK será protegida por compartimentos independentes.

Cada compartimento possuirá:
- Identificador aleatório de 16 bytes.
- Tipo de mecanismo.
- Parâmetros públicos de derivação.
- Nonce aleatório de 12 bytes.
- DEK protegida por AES-256-GCM.

A proteção da DEK produzirá 48 bytes de ciphertext e tag.

Os registros de proteção serão armazenados depois do cabeçalho.

O cabeçalho conterá somente os descritores dos compartimentos,
não os ciphertexts protegidos.

Isso evita dependência circular ao calcular a autenticação.

## 5. Compartimento FIDO2

O mecanismo FIDO2 utilizará:
- RP ID configurado do projeto.
- Credential ID necessário para localizar a credencial.
- HMAC-secret.
- Salt HMAC aleatório de 32 bytes.
- Salt HKDF independente de 32 bytes.
- HKDF-SHA256.
- Contexto de derivação exclusivo para proteção da DEK.

O resultado HMAC-secret nunca será salvo em disco.

O PIN da chave física nunca será armazenado.

Os metadados públicos serão tratados como dados não secretos.

## 6. Compartimento de recuperação

A recuperação utilizará um segredo aleatório independente de
32 bytes, gerado pelo aplicativo.

Esse segredo não dependerá da TrustKey.

A chave de proteção será derivada usando HKDF-SHA256 e um
salt independente de 32 bytes.

Não será utilizada senha humana diretamente como chave.

O armazenamento e a apresentação do segredo de recuperação
serão projetados em etapa própria.

A perda da chave física não poderá impedir a recuperação
quando o segredo independente estiver disponível.

## 7. Registros de proteção

Cada registro de proteção terá:

- Identificador do compartimento: 16 bytes.
- Nonce AES-GCM: 12 bytes.
- DEK protegida: 48 bytes.

Tamanho fixo: 76 bytes por registro.

A autenticação incluirá:
- Domínio de separação do mecanismo.
- Digest do prefixo e cabeçalho.
- Descritor original do compartimento.

Registros desconhecidos, repetidos ou ausentes serão rejeitados.

## 8. Registros de dados

Tamanho máximo inicial de dados por bloco: 1 MiB.

Cada registro terá um cabeçalho binário:

| Campo | Tamanho |
|---|---:|
| Tipo do registro | 1 byte |
| Sequência | 8 bytes |
| Comprimento do ciphertext | 4 bytes |

O ciphertext terá:
- Dados criptografados.
- Tag AES-GCM de 16 bytes.

A sequência começa em zero e cresce sem saltos.

O tamanho do ciphertext nunca poderá ultrapassar
1 MiB + 16 bytes.

## 9. Nonces dos registros

Cada contêiner terá um prefixo aleatório de 4 bytes.

O nonce de cada registro será:

prefixo de 4 bytes + contador big-endian de 8 bytes.

O contador será exclusivo dentro do contêiner.

Limite maximo inicial: 1.048.576 registros de dados por container.
Tamanho maximo dos dados compactados por registro: 1 MiB.

O registro final utilizará o próximo contador disponível.

A DEK será nova para cada contêiner.

Uma operação interrompida não poderá retomar a criptografia
reutilizando a mesma DEK e contadores.

## 10. Dados autenticados (AAD)

Cada registro de dados autenticarará:
- Domínio de separação da versão.
- Digest do prefixo e cabeçalho.
- Cabeçalho binário do registro.

A alteração do cabeçalho ou dos metadados deverá invalidar
a autenticação dos registros afetados.

O registro final também será autenticado com AES-GCM.

## 11. Fluxo de compactação

O arquivo original será lido incrementalmente.

Um único fluxo Zstandard será produzido.

O fluxo compactado será dividido em blocos de até 1 MiB.

Cada bloco será criptografado individualmente.

O checksum Zstandard será habilitado como camada adicional
de detecção de corrupção.

## 12. Registro final

O registro final terá tipo diferente dos registros de dados.

Seu conteúdo antes da criptografia será:

- Magic END1: 4 bytes.
- Quantidade de blocos: 8 bytes.
- Total de bytes compactados: 8 bytes.
- Total de bytes originais: 8 bytes.

Total: 28 bytes.

O registro final será criptografado e autenticado.

O leitor deverá rejeitar:
- Arquivo sem registro final.
- Sequência incompleta.
- Contagem divergente.
- Tamanho divergente.
- Dados posteriores ao registro final.

## 13. Restauração

A leitura deverá ocorrer nesta ordem:

1. Validar o prefixo.
2. Validar o comprimento e o cabeçalho.
3. Localizar um mecanismo de desbloqueio.
4. Recuperar a DEK.
5. Autenticar cada registro de dados.
6. Alimentar o descompressor incrementalmente.
7. Validar o registro final.
8. Confirmar o término do fluxo Zstandard.
9. Publicar o arquivo restaurado somente após a validação completa.

A saída será gravada em arquivo temporário.

Em caso de erro, o arquivo temporário deverá ser descartado.

A substituição do destino final deverá ser atômica sempre que
suportada pelo sistema.

## 14. Limites obrigatórios

A implementação deverá validar:
- Comprimento do cabeçalho.
- Quantidade de compartimentos.
- Tamanho de cada registro.
- Sequência e contador.
- Quantidade total de registros.
- Limite global de descompressão.
- Limite de memória.
- Limites criptográficos do AES-GCM.

## 15. Pastas e múltiplos arquivos

O suporte a pastas utilizará um manifesto dentro do fluxo
compactado e criptografado.

O manifesto conterá nomes relativos, tamanhos e tipos de entrada.

A extração deverá rejeitar:
- Caminhos absolutos.
- Caminhos que escapem da pasta de destino.
- Traversal com .. .
- Links simbólicos perigosos.
- Colisões de nomes.
- Arquivos duplicados.

Essa parte será implementada depois da proteção de arquivos
individuais.

## 16. Estado

Este documento não representa uma implementação pronta
ou uma auditoria criptográfica.

O formato somente será estabilizado após:
- Testes completos.
- Testes de interoperabilidade.
- Testes de falhas e truncamento.
- Testes de arquivos grandes.
- Revisão independente de segurança.