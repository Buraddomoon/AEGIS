# Licenças e proveniência

Código ÆGIS: MIT. Dependências são instaladas como componentes separados; nenhuma licença upstream é substituída pela licença do projeto. Este inventário cobre decisões principais, não substitui avaliação jurídica de distribuição.

| Componente | Licença / referência |
|---|---|
| Python | PSF License |
| FastAPI, Pydantic, SQLAlchemy, Alembic | MIT, conforme metadados upstream |
| psycopg / psycopg-binary | LGPL-3.0-only; biblioteca separada sem modificação |
| pySigma | LGPL-2.1-only; biblioteca separada sem modificação |
| React, Vite, TypeScript, Tailwind, TanStack Query, Recharts | MIT |
| Lucide | ISC, com avisos upstream de ícones |
| Argon2-cffi | MIT; backend Argon2 mantém avisos próprios |
| httpx, Uvicorn | BSD-3-Clause |
| PostgreSQL | PostgreSQL License |
| Redis Server 8 | opções AGPLv3/RSALv2/SSPLv1; distribuição como serviço separado sob opção AGPLv3 |
| redis-py | MIT; distinto da licença do servidor |
| MITRE ATT&CK dataset | Termos MITRE originais preservados em fixtures/attack/LICENSE.txt |
| Atomic Red Team | MIT upstream; comandos/testes não são distribuídos como executáveis no AEGIS |
| Sigma importado pelo usuário | Licença da regra original, não definida pelo AEGIS |
| Puppeteer Core | Apache-2.0; navegador do host possui licença própria |

Fontes oficiais: [Redis](https://redis.io/legal/licenses/), [pySigma](https://github.com/SigmaHQ/pySigma), [psycopg](https://www.psycopg.org/), [ATT&CK](https://github.com/mitre-attack/attack-stix-data), [Atomic](https://github.com/redcanaryco/atomic-red-team), [Lucide](https://lucide.dev/license).

Versões de todas as dependências Python/Node constam dos lockfiles. As licenças das distribuições Python são preservadas pelo pip em dist-info e as Node em seus pacotes. Antes de redistribuir imagens/bundles, revisar também dependências transitivas, disponibilizar avisos/fontes exigidos e registrar digests. Nenhum serviço comercial de IA ou outro serviço pago é necessário ao funcionamento principal.
