import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://vault.teuzin.com.br',
  output: 'static',
  integrations: [
    starlight({
      title: 'Teuzin Vault — Documentação',
      description: 'Guias, arquitetura, segurança e conformidade do Teuzin Vault.',
      defaultLocale: 'root',
      locales: {
        root: { label: 'Português', lang: 'pt-BR' },
      },
      customCss: ['./src/styles/starlight.css'],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/dieguesmosken/teuzin-vault' },
      ],
      sidebar: [
        { label: 'Comece aqui', items: [{ slug: 'docs/index' }, { slug: 'docs/installation' }] },
        { label: 'Produto e segurança', items: [{ slug: 'docs/architecture' }, { slug: 'docs/security' }, { slug: 'docs/recovery' }] },
        { label: 'Transparência', items: [{ slug: 'docs/licensing' }, { slug: 'docs/references' }] },
      ],
    }),
  ],
});
