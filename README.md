# Teuzin Vault

Aplicativo desktop open-source para compactação e proteção criptográfica de arquivos e pastas.

**Autor:** Matheus M. Diegues
**GitHub:** [@dieguesmosken](https://github.com/dieguesmosken)
**Projeto:** [vault.teuzin.com.br](https://vault.teuzin.com.br)

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

## Estado do projeto

Em desenvolvimento inicial. Ainda não utilizar para proteger dados importantes.

## Segurança

Consulte [SECURITY.md](SECURITY.md).

Nunca publique credenciais, PINs, tokens, arquivos `.env`, chaves privadas ou backups pessoais neste repositório.
