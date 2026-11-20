# Modelo de ameaças — Teuzin Vault

**Versão do documento:** rascunho inicial 0.1  
**Data:** 20 de novembro de 2026  
**Estado:** em revisão; não representa auditoria independente.

Este documento registra o modelo inicial do Teuzin Vault com base no código público da versão 0.1.0. Ele separa controles existentes, hipóteses e lacunas. O objetivo é orientar decisões do Marco 1; não afirmar que o aplicativo já está pronto para proteger dados críticos.

## 1. Escopo

O modelo cobre o núcleo atual de contêineres para arquivos individuais, os compartimentos de proteção da DEK, a integração FIDO2/HMAC-secret inicial no Windows, a compactação Zstandard e a publicação transacional de arquivos.

Ainda não cobre como implementado:

- interface completa de criação e restauração;
- fluxo de registro de novas credenciais FIDO2 pela interface;
- apresentação e confirmação de armazenamento do segredo de recuperação;
- manifesto, pastas e extração de múltiplos arquivos;
- integração FIDO2 nativa em Linux ou macOS;
- atualização automática, sincronização ou serviço em nuvem.

Quando essas funções forem implementadas, o modelo deverá ser atualizado antes de serem consideradas prontas.

## 2. Objetivos de segurança

1. **Confidencialidade:** quem obtiver somente o arquivo .tvault não deve conseguir recuperar o conteúdo sem um mecanismo de desbloqueio válido.
2. **Integridade e autenticidade:** modificações, reordenação, truncamento e registros extras devem ser detectados.
3. **Recuperabilidade:** a perda do autenticador físico não deve impedir a recuperação quando o segredo independente estiver disponível.
4. **Privacidade:** nomes, caminhos e conteúdo dos arquivos não devem ser expostos no cabeçalho público.
5. **Segurança operacional:** falhas de gravação ou restauração não devem publicar arquivos incompletos como se fossem válidos.
6. **Limites de recursos:** entradas malformadas e fluxos de descompressão não devem poder exigir memória ou saída ilimitadas.

## 3. Ativos que precisam de proteção

| Ativo                                            | Consequência de exposição ou perda                                                         |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Arquivo original e arquivo restaurado            | Vazamento de dados pessoais ou profissionais                                               |
| DEK de 256 bits                                  | Acesso a todo o conteúdo protegido pelo contêiner                                          |
| Resultado HMAC-secret                            | Pode derivar a chave que abre o compartimento FIDO2                                        |
| Segredo de recuperação de 256 bits               | Pode abrir o compartimento de recuperação                                                  |
| Chaves derivadas por HKDF                        | Podem abrir o compartimento correspondente                                                 |
| Conteúdo temporário em claro durante restauração | Vazamento local se o processo ou sistema for comprometido                                  |
| Metadados públicos do contêiner                  | Revelação de associação de credencial, formato, tamanhos e estrutura                       |
| Metadados locais públicos da credencial          | Exposição de identificadores e dados públicos da credencial; não equivalem ao segredo HMAC |

## 4. Limites de confiança

- **Processo do Teuzin Vault:** recebe bytes em claro e material de chave durante a criação ou restauração.
- **Sistema operacional e conta local:** controlam acesso a arquivos, memória do processo, temporários e dispositivo FIDO.
- **Autenticador físico:** mantém material simétrico vinculado à credencial e exige interação do usuário conforme a política e o dispositivo.
- **Camada WebAuthn do sistema:** intermedeia a comunicação com o autenticador e participa da validação da cerimônia.
- **Armazenamento local:** contém arquivos originais, contêineres, metadados públicos da credencial e temporários.
- **Terceiros/serviços remotos:** não há serviço remoto de desbloqueio ou armazenamento previsto no núcleo atual.

## 5. Adversários considerados

### A. Pessoa que obtém somente uma cópia do contêiner

Pode ler o cabeçalho público, copiar, apagar, substituir, truncar ou modificar registros.

**Controles existentes:** DEK aleatória; compartimentos FIDO2 e recuperação protegidos por AES-GCM; registros de dados autenticados por AES-GCM; digest do cabeçalho e metadados do registro como AAD; sequência monotônica; registro final autenticado obrigatório.

**Limite:** o contêiner ainda expõe metadados públicos e padrões de tamanho. A criptografia não impede apagar o arquivo ou impedir acesso a ele.

### B. Pessoa que adultera ou trunca o contêiner

Pode tentar alterar o cabeçalho, trocar registros, remover registros, anexar dados ou interromper o arquivo.

**Controles existentes:** validação estrita do cabeçalho, autenticação dos compartimentos, sequência dos registros, tag AEAD e registro final. O leitor rejeita registros extras após o final e a restauração publica o destino somente após a operação terminar com sucesso.

**Validação pendente:** ampliar testes de truncamento em offsets arbitrários, mutação/fuzzing dos parsers e falhas de I/O em cada estágio.

### C. Pessoa que obtém o autenticador físico

Pode tentar executar uma autenticação e recuperar o material HMAC-secret.

**Situação atual:** o adaptador solicita `user_verification="discouraged"`. Isso significa que o aplicativo não deseja exigir verificação do usuário; não equivale a exigir PIN ou biometria. A cerimônia continua validando presença, desafio, RP e assinatura conforme o fluxo WebAuthn da biblioteca, mas a política atual não exige que o bit UV esteja ativo.

**Risco pendente:** se a pessoa consegue usar fisicamente o autenticador e não há UV obrigatório, o toque/presença pode ser suficiente para obter a saída HMAC-secret. O impacto depende do autenticador, de seus próprios controles e do acesso físico. A política precisa ser decidida e testada.

**Detalhe criptográfico:** CTAP seleciona `CredRandomWithUV` ou `CredRandomWithoutUV` de acordo com o bit UV. O mesmo salt pode, portanto, produzir saídas diferentes nos dois modos. Trocar a política sem testar e migrar os compartimentos pode bloquear cofres existentes.

### D. Pessoa que obtém o segredo de recuperação

O segredo aleatório de 256 bits é suficiente para derivar a chave que abre o compartimento de recuperação.

**Controle existente:** o núcleo gera o segredo, mas não o grava automaticamente.

**Risco operacional:** quando a interface for criada, o segredo deverá ser apresentado de forma controlada, nunca incluído em logs ou telemetria, e o usuário deverá confirmar que o guardou offline. Se ele for perdido e o autenticador também não estiver disponível, não existe mecanismo mágico para recuperar a DEK.

### E. Malware executado na mesma conta ou comprometimento do sistema

Um malware com permissões suficientes pode ler arquivos originais, capturar a entrada do usuário, observar a memória do processo, trocar arquivos, controlar a interface ou tentar interagir com o autenticador.

**Fora do que a criptografia do contêiner resolve:** o Teuzin Vault não protege dados enquanto estão em claro no processo ou no sistema operacional comprometido. O aplicativo não promete resistir a malware com controle da sessão, privilégios administrativos/root ou comprometimento de firmware/hardware.

### F. Falha de energia, encerramento abrupto ou falta de espaço

Pode deixar gravações incompletas ou temporários.

**Controle existente:** a escrita usa arquivo temporário no diretório de destino e publica o resultado somente após flush/fsync e finalização; por padrão, não sobrescreve um destino existente.

**Limite:** encerramento abrupto do processo ou perda de energia pode deixar um temporário no disco. Durante a restauração, esse temporário contém plaintext. O código já documenta que não garante apagamento seguro em SSDs ou sistemas de arquivos com journaling.

### G. Reposição de uma versão antiga válida do contêiner

Um atacante pode substituir o arquivo atual por uma cópia antiga, ainda autêntica.

**Situação atual:** o formato autentica o conteúdo, mas não possui estado externo confiável para detectar rollback/replay de uma versão inteira válida. Esse cenário não é resolvido por AEAD isoladamente.

### H. Negação de serviço ou perda de disponibilidade

Um atacante pode apagar o arquivo, bloquear o disco, impedir o uso do autenticador ou causar falta de espaço.

**Situação atual:** a criptografia não substitui backup. O aplicativo não pode garantir disponibilidade contra exclusão, ransomware ou falha física do armazenamento.

## 6. Controles observados no código atual

| Área               | Controle implementado                                                                              | Limite/validação pendente                                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| DEK                | 32 bytes aleatórios por contêiner                                                                  | Revisar geração, ciclo de vida e política de reuso                                                                               |
| Compartimentos     | FIDO2 e recuperação, ambos protegendo a mesma DEK                                                  | V1 exige exatamente dois slots; extensibilidade pendente                                                                         |
| KDF                | HKDF-SHA256 e rótulos distintos por finalidade                                                     | Não usar diretamente para transformar senhas humanas em chaves                                                                   |
| Proteção de DEK    | AES-256-GCM com nonce aleatório e AAD contendo digest do cabeçalho e descritor                     | Rever atualização/rotação de slots                                                                                               |
| Registros de dados | AES-256-GCM, AAD com digest do cabeçalho e cabeçalho binário do registro                           | Revisar limites criptográficos agregados por DEK                                                                                 |
| Nonce de dados     | Prefixo aleatório de 4 bytes + sequência de 8 bytes                                                | Garantir nunca retomar operação com mesma DEK/contador                                                                           |
| Limites atuais     | 1 MiB por registro e até 1.048.576 registros de dados                                              | Isso permite até 1 TiB de payload comprimido em termos nominais; o limite deve ser revisado com análise formal de uso de AES-GCM |
| Finalização        | Registro final autenticado com contagens e tamanhos                                                | Testes adversariais adicionais                                                                                                   |
| Zstandard          | Streaming, checksum, limite de janela e limite global de saída                                     | Fuzzing e testes de carga                                                                                                        |
| Arquivos           | Temporário no diretório de destino e publicação após sucesso                                       | TOCTOU, reparse points/junctions e temporários após crash                                                                        |
| FIDO2              | Confere o Credential ID esperado contra os metadados locais; autentica com a credencial armazenada | Política UV, allowlist de origem explícita, ciclo de vida e teste por plataforma                                                 |

## 7. Metadados que podem vazar

O cabeçalho atual contém informações públicas como:

- ID aleatório do contêiner;
- algoritmos e tamanho do bloco;
- prefixo de nonce;
- tipo e descritores dos compartimentos;
- RP ID e Credential ID usados pelo compartimento FIDO2;
- salts públicos de derivação.

O fluxo também revela quantidade de registros e tamanhos aproximados do conteúdo comprimido. O conteúdo, nomes e caminhos originais não são incluídos no cabeçalho atual. Quando pastas forem implementadas, o manifesto deverá estar dentro do fluxo criptografado.

A presença de um Credential ID no cabeçalho não revela por si só o segredo HMAC-secret, mas pode permitir correlação com uma credencial conhecida. A necessidade de armazenar esse identificador publicamente deve ser revisada quanto à privacidade.

## 8. Hipóteses e exclusões explícitas

Este modelo assume:

- sistema operacional, biblioteca criptográfica, Python e dependências não comprometidos;
- autenticador genuíno e firmware sem comprometimento;
- geração aleatória funcionando corretamente;
- usuário preservando o segredo de recuperação;
- arquivos-fonte disponíveis e legíveis durante a operação.

Não promete:

- proteger plaintext de malware local ou administrador/root;
- apagar de forma irrecuperável temporários em SSDs;
- impedir exclusão, rollback ou substituição de arquivos por um atacante com acesso ao armazenamento;
- esconder tamanho, número de registros, algoritmo, RP ID ou Credential ID;
- recuperar um cofre quando todos os mecanismos de desbloqueio forem perdidos;
- proteger versões futuras de manifesto/pastas antes de essas funções serem projetadas.

## 9. Decisões abertas do Marco 1

1. **Política UV:** exigir UV, preferir UV ou manter operação sem UV? Qual será o comportamento de autenticadores que não suportam UV?
2. **Compatibilidade HMAC-secret:** como testar e migrar o compartimento FIDO2 quando UV muda e a saída HMAC pode mudar?
3. **Origem/RP:** qual política explícita deve ser validada no adaptador nativo? A constante ORIGIN está declarada, mas não é usada diretamente na construção atual do Fido2Server.
4. **Volume AES-GCM:** qual limite agregado de bytes/registros por DEK será adotado e como será imposto?
5. **Compartimentos:** manter exatamente FIDO2 + recuperação no V1 ou introduzir estrutura extensível antes de estabilizar?
6. **Segredo de recuperação:** qual formato, exibição, confirmação, cópia offline e procedimento de teste serão adotados?
7. **Temporários:** qual política de localização, permissões, limpeza pós-crash e aviso ao usuário será implementada?
8. **Privacidade:** é necessário manter o Credential ID no cabeçalho público ou há alternativa segura de lookup?

Nenhuma dessas decisões está marcada como resolvida neste rascunho.

## 10. Critérios para avançar

- [ ] Revisar este rascunho com o mantenedor.
- [ ] Registrar decisões UV e compatibilidade HMAC-secret em ADR.
- [ ] Validar comportamento do autenticador real com e sem UV.
- [ ] Definir limites AES-GCM com referência normativa e teste de fronteira.
- [ ] Definir política de segredo de recuperação.
- [ ] Especificar mitigação de temporários e falhas abruptas.
- [ ] Expandir testes adversariais e fuzzing.
- [ ] Submeter o desenho do formato a revisão independente antes de declarar V1 estável.

## 11. Referências

- [W3C Web Authentication Level 3 — Recommendation (25/08/2026)](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/) — semântica de UP, UV e userVerification.
- [FIDO Alliance CTAP 2.3 — Proposed Standard (26/02/2026)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html) — comportamento HMAC-secret e escolha de CredRandom conforme UV.
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) — AES-GCM.
- [Código do adaptador FIDO2](../src/teuzin_vault/fido2/authenticator.py).
- [Formato e validação do cabeçalho](../src/teuzin_vault/core/container_format.py).
- [Registros autenticados](../src/teuzin_vault/core/records.py).
- [Proteção de chaves](../src/teuzin_vault/core/key_protection.py).
- [Operações transacionais de arquivo](../src/teuzin_vault/core/file_operations.py).
