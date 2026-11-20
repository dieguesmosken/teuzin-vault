# Requisitos de plataforma — migração futura para Linux

**Estado:** planejamento futuro, não faz parte do Marco 1 do Teuzin Vault.  
**Data de registro:** 20 de novembro de 2026.

## 1. Requisito do usuário

Na migração do Windows para Linux, preservar a experiência atual com downloads:

- O navegador (atualmente Chrome e Edge) encaminha downloads para um gerenciador externo.
- O gerenciador oferece fila, pausa/retomada e aceleração/segmentação quando suportada pelo servidor.
- Quando o download termina de verdade, o arquivo passa por uma análise antivírus seletiva com o Kaspersky.
- O usuário consegue ver o resultado da análise.
- Um arquivo não deve ser tratado como limpo se a análise falhar, for cancelada ou o mecanismo antivírus estiver indisponível.

A prioridade é preservar a verificação pelo Kaspersky, não necessariamente preservar a mesma interface do FDM.

## 2. Candidato A — Free Download Manager para Linux

O site oficial do FDM lista atualmente versão Linux, com pacote DEB e distribuição pelo Flathub. A página também lista extensões oficiais para Chrome e Firefox.

**O que ainda precisa ser testado na distribuição Linux escolhida:**

- instalação e atualização;
- captura de downloads pelo Chrome;
- integração com Edge (não assumir compatibilidade sem teste);
- filas, retomada e downloads segmentados;
- existência de mecanismo suportado para chamar um antivírus externo após conclusão;
- se o FDM espera o resultado do antivírus ou apenas dispara uma ação.

A disponibilidade do FDM para Linux não comprova, por si só, que a integração externa com Kaspersky reproduz o comportamento atual do Windows.

Referência: [Free Download Manager — download oficial](https://www.freedownloadmanager.org/download.htm).

## 3. Candidato B — aria2 com interface e integração de navegador

O aria2 é uma alternativa open-source para o motor de downloads. A documentação oficial descreve o evento --on-download-complete, executado após a conclusão do download, e os argumentos fornecidos ao hook incluem GID, número de arquivos e caminho.

Uma composição possível:

- aria2 como motor;
- AriaNg como interface de gerenciamento;
- extensão/conector compatível com o navegador para enviar downloads;
- pequeno serviço local nosso para receber o evento e solicitar a análise ao antivírus.

O serviço de integração precisa tratar o caminho do arquivo como dado não confiável. Não deve concatenar o caminho numa string de shell; deve invocar processos com argumentos separados e validar a identidade do arquivo.

Referências:

- [aria2 — documentação oficial e event hooks](https://aria2.github.io/manual/en/html/aria2c.html).
- [AriaNg — interface open-source](https://github.com/mayswind/AriaNg).
- [aria2 — repositório](https://github.com/aria2/aria2).

## 4. Kaspersky no Linux

A Kaspersky anunciou uma versão doméstica para Linux em 3 de novembro de 2025 e informa suporte para Ubuntu 24.04+, ALT Linux 10+, RedOS 7+ e Uncom 2.3.5+ na página de requisitos consultada.

A Kaspersky informa que o produto doméstico para Linux monitora o sistema e dispositivos e verifica arquivos, pastas e aplicações. A existência de um comando CLI suportado para verificar um arquivo individual, a possibilidade de ser chamado por um hook e o comportamento de quarentena precisam ser confirmados na versão instalada e na licença do usuário.

Não assumir que ferramentas diferentes da Kaspersky são equivalentes:

- O KVRT para Linux é uma ferramenta portátil de verificação sob demanda.
- A própria Kaspersky informa que o KVRT Linux não oferece atualização automática de bases nem agendamento de análises; portanto, não é o candidato preferencial para a verificação automática de cada download.

Referências:

- [Kaspersky for Linux — anúncio para usuários domésticos](https://www.kaspersky.com/blog/kaspersky-for-linux/54697/).
- [Kaspersky for Linux — produto e requisitos](https://www.kaspersky.com/linux-antivirus).
- [KVRT for Linux — limitações e modo de uso](https://www.kaspersky.com/blog/kvrt-for-linux/51375/).

## 5. Fluxo de segurança desejado

1. O navegador encaminha o download ao gerenciador.
2. O arquivo é gravado numa área de staging/downloads ainda não confiável.
3. O gerenciador informa que o download foi concluído, não apenas pausado ou interrompido.
4. O serviço de integração solicita uma análise ao Kaspersky por uma interface oficialmente suportada.
5. O serviço aguarda e registra o resultado.
6. Só um resultado confirmado como limpo libera o arquivo para o fluxo normal.
7. Detecção, erro, cancelamento ou indisponibilidade mantêm o arquivo em estado pendente/quarentena e notificam o usuário.

O padrão de falha deve ser **fail closed**: ausência de resposta do antivírus não é resultado limpo. Não remover arquivos automaticamente sem uma política explícita e confirmação do usuário.

## 6. Testes de aceitação antes da migração

- [ ] FDM Linux captura downloads do navegador escolhido.
- [ ] Alternativa aria2 captura downloads do navegador escolhido.
- [ ] Pausa, retomada, fila e downloads grandes funcionam.
- [ ] O hook só inicia após a conclusão real e arquivo fechado.
- [ ] Arquivos com espaços, Unicode, caracteres especiais e nomes longos são tratados corretamente.
- [ ] Paths não podem injetar comandos no serviço de integração.
- [ ] O serviço espera o resultado completo da análise.
- [ ] Falha ou indisponibilidade do Kaspersky não libera o arquivo.
- [ ] Arquivos detectados ficam isolados e a ação do usuário é clara.
- [ ] Arquivos compactados e protegidos por senha exibem o resultado/limitação corretamente.
- [ ] Teste com arquivo de teste antivírus (EICAR) em ambiente controlado; nunca usar malware real.
- [ ] O sistema registra estado e resultado sem vazar conteúdo, URLs com tokens ou dados privados em logs.

## 7. Momento de implementação

Esta trilha só deve ser executada quando o usuário escolher a distribuição e a versão do Linux para a migração. Primeiro testar o FDM oficial. Se ele não oferecer uma integração suportada com o Kaspersky, avaliar aria2 + serviço local de integração. Desenvolver um gerenciador próprio completo é o último recurso, não o primeiro.
