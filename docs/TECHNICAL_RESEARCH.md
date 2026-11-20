# Pesquisa técnica e oportunidades — Teuzin Vault

**Data da pesquisa:** 20 de novembro de 2026  
**Escopo:** arquitetura atual do repositório, referências oficiais e projetos open-source relacionados.  
**Status:** recomendações para avaliação; não são decisões criptográficas finais.

## 1. O que foi observado no código atual

A primeira versão pública já tem:
- AES-256-GCM por registro, com AAD derivado do cabeçalho e metadados do registro.
- DEK aleatória e compartimentos autenticados para FIDO2/HMAC-secret e recuperação.
- HKDF-SHA256 com rótulos de finalidade diferentes.
- Um fluxo Zstandard incremental, com checksum habilitado e limites de janela e saída na descompressão.
- Escrita transacional para arquivos individuais, usando temporário e publicação final.
- Adaptador FIDO2 inicial limitado ao Windows.

Ainda não estão completos:
- UI além da janela inicial.
- Fluxo de criação/registro de novo autenticador pela interface.
- Apresentação e armazenamento orientado do segredo de recuperação.
- Manifesto e extração segura de pastas.
- Suporte de autenticador em Linux/macOS.
- Revisão externa de segurança.

O formato atual exige exatamente dois compartimentos de chave (FIDO2 e recuperação) e usa uma única DEK por contêiner. Alterar essa estrutura depois de existirem arquivos reais exigirá uma política de versão/migração.

## 2. Criptografia e gerenciamento de chaves

### 2.1 Manter HKDF para segredos aleatórios

HMAC-secret e o segredo de recuperação atual têm 256 bits aleatórios. HKDF-SHA256 é apropriado para derivar chaves de finalidade específica a partir de material de alta entropia. Os rótulos separados já ajudam a evitar reutilização acidental entre contextos.

**Não trocar HKDF por Argon2id para esses segredos aleatórios sem motivo.** Argon2id é especialmente relevante quando o segredo inicial é uma senha humana, que pode ter baixa entropia.

### 2.2 Argon2id como compartimento opcional de senha

Uma senha adicional pode ser útil para quem não possui uma chave FIDO2 disponível. Para senha humana, avaliar Argon2id, salt único por contêiner, parâmetros armazenados no descritor e limites rigorosos para impedir que cabeçalhos maliciosos forcem consumo excessivo de memória.

A RFC 9106 descreve Argon2id e fornece opções de referência (2 GiB com uma passagem ou 64 MiB com três passagens). Esses valores não devem ser copiados cegamente: o aplicativo precisa calibrar parâmetros para computadores reais, garantir compatibilidade e limitar os parâmetros aceitos durante a abertura.

**Prioridade:** média, depois de concluir a recuperação e tornar o formato extensível.

### 2.3 Política de User Verification no FIDO2

O adaptador atual chama `authenticate_begin(..., user_verification="discouraged")`. Isso não deve ser tratado como uma decisão definitiva de segurança. Precisamos definir se a posse física/toque é suficiente ou se a operação deve exigir UV (por exemplo, PIN ou biometria), verificar como Windows WebAuthn e cada autenticador aplicam a política e testar o comportamento real.

O HMAC-secret é um segredo simétrico vinculado à credencial. Aplicativos nativos precisam cuidar de separação de domínio, uso exclusivo do resultado, vida útil curta do material sensível e limpeza de memória sempre que tecnicamente possível. Em Python, objetos `bytes` imutáveis e o gerenciamento de memória do runtime impedem prometer apagamento garantido; isso precisa constar no modelo de ameaças.

### 2.4 RP ID é uma decisão de longo prazo

O autenticador guarda a credencial no escopo do RP ID. Mudar de `vault.teuzin.com.br` para outro domínio não é uma simples troca de configuração: credenciais vinculadas ao RP ID antigo não se tornam credenciais do novo RP ID. Manter essa identidade estável antes de distribuir amplamente o aplicativo é importante.

### 2.5 Avaliar AEADs sem improvisar

AES-256-GCM é um AEAD amplamente utilizado e o código já usa nonces de 96 bits com contador por contêiner. A revisão deve confirmar unicidade, limite de bytes/registros por chave, comportamento em falhas e nunca retomar uma operação com a mesma DEK e contadores potencialmente reutilizados.

Duas alternativas merecem benchmark e análise antes de congelar o formato:
- **XChaCha20-Poly1305 / libsodium secretstream:** a API secretstream fornece tags de fim de fluxo, detecção de truncamento/reordenação e rekeying automático, sendo desenhada para streams de tamanho grande.
- **AES-GCM-SIV:** especificado na RFC 8452, reduz o impacto catastrófico de repetição acidental de nonce, com custo adicional de desempenho e diferenças de implementação.

Não misturar algoritmos silenciosamente dentro do V1. Qualquer mudança exige identificador de suite, vetores de teste, documentação e compatibilidade explícita.

## 3. Zstandard: oportunidades de compressão

A implementação de streaming atual já ativa `checksum_flag`, impõe uma janela máxima na descompressão e rejeita quadros incompletos ou dados posteriores. É uma boa base conservadora.

O módulo `compression.zstd` da biblioteca padrão do Python (disponível desde Python 3.14) expõe opções avançadas:
- Níveis de compressão e estratégias com diferentes trocas entre velocidade e taxa.
- `nb_workers` para compressão multithread, aumentando velocidade potencial, memória usada e, em alguns casos, reduzindo um pouco a taxa.
- Long-distance matching para entradas grandes, com impacto de memória e janela.
- Treinamento de dicionários, útil sobretudo em lotes de dados pequenos e semelhantes.

**Plano de desempenho recomendado:**
1. Criar corpus de benchmark (texto, código, PDF, imagens, vídeos, ZIP/7z, binários e dados aleatórios).
2. Comparar níveis baixo, padrão e alto.
3. Medir tempo, memória máxima, CPU e tamanho final.
4. Só então disponibilizar perfis Rápido, Equilibrado e Melhor taxa.
5. Manter limites rígidos de descompressão, mesmo ao elevar nível ou ativar workers.

Dicionários precisam ser identificados/versionados e disponíveis para restauração. Eles não devem ser uma dependência remota obrigatória. Para arquivos já compactados ou de alta entropia, o aplicativo deve evitar gastar CPU tentando obter economia insignificante.

### Quadros independentes e acesso aleatório

O formato Seekable Zstandard divide o fluxo em quadros independentes e registra um índice para localizar partes sem descompactar tudo. Isso pode ajudar em restauração seletiva e acesso parcial, mas quadros menores podem reduzir a taxa de compressão e aumentar o overhead.

**Prioridade:** posterior ao fluxo de arquivos/pastas convencional; medir antes de adicionar índice ao contêiner.

## 4. Pastas, manifesto e restauração segura

O manifesto de arquivos e diretórios deve permanecer dentro do fluxo criptografado. Caminhos e nomes expostos no cabeçalho podem revelar informação privada.

Na extração, validar cada entrada antes de criar qualquer arquivo:
- aceitar somente caminhos relativos normalizados;
- rejeitar caminhos absolutos, componentes `..`, UNC e caminhos que escapem do destino;
- definir política para links simbólicos, junctions/reparse points e arquivos especiais;
- detectar colisões em sistemas case-insensitive e nomes reservados do Windows;
- impedir gravação por Alternate Data Streams, quando não suportados pelo formato;
- limitar quantidade de entradas, comprimento de caminhos, tamanho total e expansão;
- usar diretório temporário e publicar o resultado somente depois da validação.

A função atual de arquivo individual já tenta impedir links simbólicos e publicar temporários atomicamente. A implementação de pastas precisa cobrir também reparse points/junctions no Windows e condições de corrida entre validação e abertura.

## 5. Ideias de funcionalidades

| Ideia | Benefício | Prioridade sugerida |
|---|---|---|
| Verificar integridade do cofre | Permite testar sem substituir arquivos restaurados | Alta |
| Progresso e cancelamento seguro | UX para arquivos grandes | Alta |
| Segundo autenticador físico | Reduz risco de perda da chave principal | Alta |
| Rotação/adição de compartimentos | Atualiza acessos sem recriptografar todo o conteúdo, se o formato permitir | Média |
| Senha opcional com Argon2id | Alternativa ao hardware | Média |
| Perfis de compressão | Ajusta velocidade e tamanho | Média |
| Restauração seletiva | Recupera apenas alguns arquivos | Média |
| Quadros seekable | Acesso parcial e recuperação mais rápida | Média/baixa |
| Backup incremental/deduplicação | Economiza espaço em conjuntos grandes | Baixa; envolve riscos de privacidade |
| Volumes divididos | Facilita mídias com limite de tamanho | Baixa |

Deduplicação merece cautela: deduplicar com base em hashes ou identificadores previsíveis pode revelar que dois arquivos são iguais. Uma solução criptográfica de deduplicação exige threat model próprio; não deve ser adicionada como otimização simples.

## 6. Testes e qualidade

Expandir os 132 testes atuais com:
- fuzzing do cabeçalho JSON, parsers binários, registros e manifesto;
- testes de truncamento em cada byte de cabeçalho/registro;
- adulteração, reordenação, duplicação, remoção e concatenação de registros;
- quadros Zstandard incompletos, extras, inválidos e bombas de descompressão;
- propriedades e testes aleatórios para round-trip;
- arquivos grandes, arquivos esparsos e fontes alteradas durante leitura;
- falta de espaço, permissões, falhas de disco e cancelamento;
- diretórios com nomes problemáticos, junctions, symlinks e colisões;
- CI em Windows e Linux, além das versões de Python suportadas.

Para a interface, as operações de I/O e criptografia devem ficar fora da thread principal. Mensagens de erro devem ser úteis sem revelar segredos, dados internos ou conteúdo de arquivos.

## 7. Referências consultadas

1. [Python 3.15 — compression.zstd](https://docs.python.org/3/library/compression.zstd.html) — opções, streaming, workers, checksums e dicionários.
2. [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) — parâmetros e recomendações para Argon2id.
3. [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) — especificação e requisitos de GCM; o NIST informa que a publicação está em revisão.
4. [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452) — AEAD com resistência a uso acidental repetido de nonce.
5. [Libsodium — secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream) — criptografia autenticada de streams, tags finais e rekeying.
6. [FIDO Alliance — CTAP 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html) — definição do HMAC-secret.
7. [Yubico — CTAP2 HMAC-secret Deep Dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html) — threat model para aplicativos nativos, derivação e tratamento de segredo.
8. [Meta / Zstandard — Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format) — quadros independentes e índice para acesso aleatório.
9. [GitHub Docs — publicar com GitHub Actions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site) — fluxo oficial de publicação de Pages.

## 8. Conclusão da pesquisa

A melhor evolução não é adicionar o máximo de opções agora. É congelar um formato bem definido, criar a interface para o fluxo simples de arquivo individual, finalizar a recuperação, adicionar suporte seguro a pastas e só depois otimizar compressão e recursos avançados com benchmarks e testes. A revisão independente deve acontecer antes de divulgar uma versão estável.
