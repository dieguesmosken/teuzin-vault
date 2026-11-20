# Roadmap — Teuzin Vault

**Última atualização:** 20 de novembro de 2026  
**Versão de desenvolvimento:** 0.1.0  
**Estado geral:** experimental

Este roadmap é vivo. As etapas podem mudar após testes, pesquisa, revisão de segurança ou feedback. Não representa promessa de prazo nem garantia de que todas as ideias serão implementadas.

## Visão do produto

Criar um aplicativo desktop local, open-source e multiplataforma para compactar e proteger arquivos e pastas. O desbloqueio deve admitir um autenticador físico FIDO2 com HMAC-secret e uma forma de recuperação independente. O usuário deve conseguir verificar a integridade e restaurar seus dados sem depender de um serviço em nuvem.

## Marcos

### Marco 0 — Núcleo inicial

<sub>Concluído em 20/11/2026</sub>

- [x] Estrutura Python e dependências iniciais.
- [x] Primitivas de AES-256-GCM e HKDF-SHA256.
- [x] Formato preliminar do cabeçalho e registros autenticados.
- [x] Compartimentos independentes para FIDO2/HMAC-secret e recuperação.
- [x] Compactação e descompactação Zstandard em fluxo.
- [x] Operações transacionais para arquivos individuais.
- [x] Suíte inicial com 132 testes aprovados.
- [x] Primeiro commit publicado no GitHub.

**Limite deste marco:** os testes automatizados não equivalem a uma auditoria criptográfica. O formato ainda não está congelado e a interface ainda é um esqueleto.

### Marco 1 — Revisão do formato e do modelo de segurança

<sub>Prioridade atual · antes de declarar o formato estável</sub>

- [x] Publicar o rascunho inicial do modelo de ameaças, identificando ativos, adversários, controles existentes e lacunas.
- [ ] Revisar o modelo com o mantenedor e validar os cenários e prioridades.
- [ ] Decidir a política de User Verification (UV) e testar PIN/UV em autenticadores reais.
- [ ] Testar o impacto de UV e não-UV no resultado HMAC-secret, incluindo a recuperação/reproteção de credenciais já registradas.
- [ ] Confirmar o RP ID e as implicações de manter `vault.teuzin.com.br` como identidade da credencial.
- [ ] Revisar limites de AES-GCM, contadores, quantidade de registros, bytes totais e ciclo de vida da DEK.
- [ ] Decidir se o formato precisa de compartimentos extensíveis ou se a restrição FIDO2 + recuperação será mantida no V1.
- [ ] Definir quais metadados precisam permanecer ocultos.
- [ ] Especificar comportamento de falhas, cancelamento, arquivos parciais e restauração atômica.
- [ ] Ampliar testes de adulteração, truncamento, fuzzing e entradas malformadas.
- [ ] Não congelar o formato V1 antes de revisão técnica suficiente.

### Marco 2 — Interface desktop com PySide6

<sub>Próxima fase de produto</sub>

- [x] Criar janela principal com identidade visual consistente.
- [x] Criar tela inicial, restauração de arquivo individual e página Sobre.
- [ ] Criar o fluxo de criação de novos cofres pela interface.
- [x] Implementar seleção de cofre e destino por diálogos nativos.
- [ ] Adicionar suporte a arrastar e soltar arquivos.
- [ ] Não mostrar segredos em logs, mensagens de erro ou histórico.
- [ ] Adicionar acessibilidade básica, atalhos e mensagens claras.

### Marco 3 — Fluxo completo para arquivos individuais

- [ ] Integrar a interface ao núcleo já testado.
- [ ] Criar um cofre com DEK aleatória e compartimentos de desbloqueio.
- [ ] Realizar autenticação FIDO2 e recuperação independente.
- [ ] Exibir o segredo de recuperação de forma segura, com confirmação de cópia/armazenamento.
- [ ] Restaurar para arquivo temporário e publicar somente após validar o fluxo completo.
- [ ] Implementar verificação de integridade sem sobrescrever arquivos existentes.
- [ ] Cobrir arquivos vazios, pequenos, grandes, bloqueados e modificados durante a operação.

### Marco 4 — Pastas e múltiplos arquivos

- [ ] Definir manifesto interno, autenticado e criptografado.
- [ ] Preservar estrutura relativa de diretórios.
- [ ] Validar caminhos antes de extrair: rejeitar caminhos absolutos, `..`, colisões e nomes inválidos.
- [ ] Tratar links simbólicos, junctions/reparse points e arquivos especiais com política explícita.
- [ ] Tratar diferenças entre Windows e Linux, incluindo maiúsculas/minúsculas, nomes reservados e Alternate Data Streams.
- [ ] Permitir restauração seletiva somente depois de validar as regras do manifesto.
- [ ] Testar rollback e limpeza de temporários após falhas.

### Marco 5 — Recuperação e gerenciamento de chaves

- [ ] Definir um formato legível e verificável para o segredo de recuperação.
- [ ] Oferecer instruções para manter cópia offline e testar a recuperação.
- [ ] Avaliar suporte a mais de um autenticador físico.
- [ ] Avaliar adicionar/remover compartimentos e reempacotar a DEK sem recriptografar todo o conteúdo.
- [ ] Avaliar senha opcional usando Argon2id, somente se houver demanda e parâmetros calibrados.
- [ ] Não usar HKDF como substituto de uma KDF resistente a ataques de dicionário para senhas humanas.
- [ ] Documentar perda do autenticador, perda do segredo de recuperação e rotação.

### Marco 6 — Compactação e desempenho

- [ ] Criar benchmarks reproduzíveis com texto, código, imagens, vídeos, arquivos compactados e dados aleatórios.
- [ ] Comparar perfis Rápido, Equilibrado e Melhor taxa.
- [ ] Medir tempo, tamanho final, memória e uso de CPU.
- [ ] Avaliar multithreading do Zstandard com limites de memória.
- [ ] Avaliar dicionários para conjuntos de arquivos pequenos e semelhantes.
- [ ] Avaliar quadros independentes e índice seekable para restauração parcial.
- [ ] Detectar quando a compactação não traz benefício e evitar trabalho desnecessário.
- [ ] Manter checksum e limites de janela/saída na descompactação.
- [ ] Só adotar mudanças que tragam benefício medido sem comprometer interoperabilidade.

### Marco 7 — Qualidade, segurança e compatibilidade

- [ ] CI automatizada em Windows e Linux.
- [ ] Testes nas versões de Python suportadas.
- [ ] Fuzzing do parser do contêiner, registros, manifesto e descompactador.
- [ ] Testes de propriedade e casos gerados aleatoriamente.
- [ ] Verificação de dependências, análise estática e detecção de segredos.
- [ ] Revisão de permissões, temporários, logs e tratamento de memória sensível.
- [ ] Guia de instalação, atualização, backup e recuperação.
- [ ] Revisão independente de segurança antes de uma versão estável.

### Marco 8 — Distribuição e recursos avançados

- [ ] Empacotamento Windows.
- [ ] Adaptador FIDO2 para Linux e avaliação de macOS.
- [ ] Builds reproduzíveis e assinatura dos artefatos, quando viável.
- [ ] Atualizações e notas de versão.
- [ ] Avaliar cofres divididos em volumes.
- [ ] Avaliar backups incrementais e deduplicação, com análise explícita de vazamento de padrões.
- [ ] Avaliar verificação, listagem e restauração seletiva sem extrair tudo.
- [x] Publicar o site do projeto no GitHub Pages com domínio próprio e HTTPS.
- [ ] Manter site, README, roadmap e documentação sincronizados a cada marco.

## Critérios para uma versão estável

Uma versão estável exige, no mínimo:

1. Formato documentado e congelado, com regras de compatibilidade e migração.
2. Criação, desbloqueio, recuperação e restauração testados ponta a ponta.
3. Proteção contra truncamento, adulteração, traversal e descompressão excessiva.
4. Testes em sistemas suportados e autenticação com hardware real.
5. Processo documentado de vulnerabilidades e revisão independente.
6. Avisos claros sobre limites, backup e perda de credenciais.

## Fora do escopo inicial

Não serão prioridades para o V1: sincronização em nuvem, servidor de contas, compartilhamento social, deduplicação global, edição online e promessas de recuperação de dados sem uma chave válida.

---

**Como acompanhar:** cada marco concluído deve ter testes, revisão de arquivos/segredos, atualização deste roadmap e commit próprio no repositório.


## Requisito futuro — migração Linux

A migração de plataforma deverá preservar a experiência atual de downloads e a checagem antivírus automática. Os requisitos e candidatos avaliados estão em [docs/PLATFORM_MIGRATION.md](docs/PLATFORM_MIGRATION.md). Essa trilha é planejamento futuro e não altera a prioridade atual do núcleo do Teuzin Vault.
