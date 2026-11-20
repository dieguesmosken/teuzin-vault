# Teuzin Vault

Aplicativo desktop experimental para compactação e proteção criptográfica local de arquivos.

**Autor:** Matheus M. Diegues  
**GitHub:** [@dieguesmosken](https://github.com/dieguesmosken)  
**Site oficial:** [https://vault.teuzin.com.br](https://vault.teuzin.com.br)  
**Código-fonte:** [github.com/dieguesmosken/teuzin-vault](https://github.com/dieguesmosken/teuzin-vault)

> **Aviso:** o Teuzin Vault está em desenvolvimento experimental. Não utilize esta versão como única cópia de arquivos importantes ou backups críticos. O projeto ainda não passou por auditoria independente.

## Estado atual

**Versão de desenvolvimento: 0.1.0.**

- Núcleo criptográfico com AES-256-GCM e HKDF-SHA256.
- Contêiner TVLT V1 preliminar, com registros autenticados.
- Compartimentos independentes para FIDO2/HMAC-secret e recuperação.
- Política de verificação do usuário obrigatória no fluxo FIDO2 validado em Yubico real.
- Migração do compartimento FIDO2 para UV obrigatório, preservando o compartimento de recuperação e o arquivo original.
- Interface desktop PySide6 com restauração inicial de arquivos individuais.
- Suíte automatizada: 146 testes passaram na validação da primeira entrega da interface em 20/11/2026.

A criação de novos cofres pela interface, o suporte a pastas e múltiplos arquivos, arrastar e soltar, progresso mensurável e cancelamento seguro ainda estão em desenvolvimento.

## Tecnologias

- Python 3.14+
- PySide6
- python-fido2
- cryptography
- Zstandard por `compression.zstd` (Python 3.14+)
- pytest
- Astro + Starlight para o site e a documentação

## Desenvolvimento

Consulte [Instalação e desenvolvimento](https://vault.teuzin.com.br/docs/installation/) e o [roadmap](ROADMAP.md).

## Documentação e transparência

- [Documentação oficial](https://vault.teuzin.com.br/docs/)
- [Modelo de ameaças](docs/THREAT_MODEL.md)
- [Pesquisa técnica](docs/TECHNICAL_RESEARCH.md)
- [Migração de plataforma](docs/PLATFORM_MIGRATION.md)
- [Licenças e política de atribuição](docs/LICENSES.md)
- [Avisos de terceiros](THIRD_PARTY_NOTICES.md)
- [Referências técnicas](docs/REFERENCES.md)
- [Inventário de software (SBOM)](docs/SOFTWARE_BILL_OF_MATERIALS.md)

## Licença

O código original do Teuzin Vault está sob [Apache License 2.0](LICENSE). Dependências, ferramentas, fontes, componentes nativos e outros materiais de terceiros mantêm suas próprias licenças. Consulte [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Segurança

Consulte [SECURITY.md](SECURITY.md). Nunca publique credenciais, PINs, tokens, arquivos `.env`, chaves privadas, segredos de recuperação ou backups pessoais neste repositório.
