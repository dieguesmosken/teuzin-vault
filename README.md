# Teuzin Vault

Aplicativo desktop open-source para compactação e proteção criptográfica de arquivos e pastas.

**Autor:** Matheus M. Diegues  
**GitHub:** [@dieguesmosken](https://github.com/dieguesmosken)  
**Projeto:** [site temporário no GitHub Pages](https://dieguesmosken.github.io/teuzin-vault/)  
**Domínio planejado:** [vault.teuzin.com.br](https://vault.teuzin.com.br)

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

**Versão de desenvolvimento: 0.1.0 — núcleo inicial publicado.**

A primeira entrega contém o núcleo criptográfico, formato preliminar do contêiner, proteção da DEK por compartimentos FIDO2 e recuperação, compactação incremental e operações transacionais para arquivos individuais.

A interface atual é somente uma janela inicial. O suporte completo a pastas, recuperação pela interface e formato estável ainda estão pendentes.

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

## Site e atualizações

O site temporário do projeto será publicado no GitHub Pages por GitHub Actions:

- [Abrir site do Teuzin Vault](https://dieguesmosken.github.io/teuzin-vault/)
- [Acompanhar o roadmap](ROADMAP.md)
- [Ver alterações e marcos](https://github.com/dieguesmosken/teuzin-vault/commits/main)

O domínio `vault.teuzin.com.br` será configurado em uma etapa posterior, quando a estrutura do site estiver consolidada.

## Segurança

Consulte [SECURITY.md](SECURITY.md).

Nunca publique credenciais, PINs, tokens, arquivos `.env`, chaves privadas, segredos de recuperação ou backups pessoais neste repositório.
