# Teuzin Vault

Aplicativo desktop open-source para compactação e proteção criptográfica de arquivos e pastas.

**Autor:** Matheus M. Diegues  
**GitHub:** [@dieguesmosken](https://github.com/dieguesmosken)  
**Site oficial:** [https://vault.teuzin.com.br](https://vault.teuzin.com.br)  
**Código-fonte:** [github.com/dieguesmosken/teuzin-vault](https://github.com/dieguesmosken/teuzin-vault)

> **Aviso:** o Teuzin Vault está em desenvolvimento experimental. Não utilize esta versão para proteger a única cópia de arquivos importantes ou backups críticos.

## Objetivos

- Selecionar arquivos e pastas para proteção.
- Compactar dados usando Zstandard.
- Criptografar dados com AES-256-GCM.
- Integrar autenticadores físicos FIDO2 compatíveis com HMAC-secret.
- Derivar chaves com HKDF-SHA256.
- Oferecer recuperação independente do autenticador físico.
- Disponibilizar uma interface desktop simples.

## Tecnologias

- Python 3.14+
- PySide6
- python-fido2
- cryptography
- Zstandard (`compression.zstd`, biblioteca padrão do Python 3.14+)
- pytest

## Estado atual

**Versão de desenvolvimento: 0.1.0 — restauração inicial pela interface desktop.**

A primeira entrega contém o núcleo criptográfico, formato preliminar do contêiner, proteção da DEK por compartimentos FIDO2 e recuperação, compactação incremental e operações transacionais para arquivos individuais.

A interface desktop agora oferece restauração de arquivos individuais TVLT V1. O usuário pode desbloquear o cofre com FIDO2 no Windows, exigindo verificação do usuário (PIN ou biometria), ou utilizar o segredo independente de recuperação. A operação acontece em segundo plano, com limite configurável para o tamanho restaurado e sem sobrescrever destinos existentes.

A criação de novos cofres pela interface, o suporte a pastas e múltiplos arquivos, arrastar e soltar e o indicador de progresso detalhado ainda estão pendentes.

## Roadmap

O planejamento completo, com etapas e critérios de conclusão, está em [ROADMAP.md](ROADMAP.md).

### Próximos marcos

1. Revisar o modelo de ameaças, a política de verificação FIDO2 e os limites do formato.
2. Construir a estrutura da interface desktop com PySide6.
3. Integrar o fluxo de criação e restauração de arquivos individuais.
4. Implementar manifesto e extração segura de pastas.
5. Finalizar a experiência de recuperação e gerenciamento de autenticadores.

As etapas não possuem datas prometidas. Segurança, testes e compatibilidade têm prioridade sobre velocidade de entrega.

## Pesquisa técnica

As oportunidades, referências e decisões em avaliação estão documentadas em [docs/TECHNICAL_RESEARCH.md](docs/TECHNICAL_RESEARCH.md).  
O primeiro rascunho do modelo de ameaças está em [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).  
Os requisitos futuros de compatibilidade e migração Linux estão em [docs/PLATFORM_MIGRATION.md](docs/PLATFORM_MIGRATION.md).

## Site e atualizações

O site oficial do projeto é publicado no GitHub Pages por GitHub Actions:

- [Abrir site do Teuzin Vault](https://vault.teuzin.com.br/)
- [Acompanhar o roadmap](ROADMAP.md)
- [Ver alterações e marcos](https://github.com/dieguesmosken/teuzin-vault/commits/main)

O domínio personalizado `vault.teuzin.com.br` está configurado com HTTPS obrigatório.

## Segurança

Consulte [SECURITY.md](SECURITY.md).

Nunca publique credenciais, PINs, tokens, arquivos `.env`, chaves privadas, segredos de recuperação ou backups pessoais neste repositório.
