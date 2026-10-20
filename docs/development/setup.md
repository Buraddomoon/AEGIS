# Ambiente de desenvolvimento

Use Python 3.13 e Node 24. Na máquina inicial, o interpretador está em `/home/IVPTER/.pyenv/versions/3.13.14/bin/python`; esse caminho não é requisito para outros desenvolvedores.

1. `make PYTHON=/caminho/python3.13 setup` cria venv, instala locks e gera `.env` privado.
2. `make infra` inicia apenas os serviços ÆGIS PostgreSQL/Redis, com portas loopback 18782/18783. Não utiliza bancos de outros projetos.
3. `make migrate` e `.venv/bin/python -m aegis.cli seed`.
4. `.venv/bin/python -m aegis.cli bootstrap` cria seu administrador.
5. Terminais separados: `make dev-api`, `make dev-worker`, `make dev-web`.

Vite atende 18780 e faz proxy `/api` para FastAPI 18781. Configure `PUBLIC_ORIGIN` com o endereço exato utilizado, incluindo esquema/porta. Não misture localhost e 127.0.0.1 no browser. `SECURE_COOKIES=false` se limita ao HTTP local. Não existe CORS permissivo.

O Compose completo e o Vite usam a mesma porta 18780; interrompa os serviços de aplicação antes de desenvolver com Vite. Banco/Redis podem continuar ativos. `make down` não remove volumes; o override de desenvolvimento continua associado ao projeto até os containers serem recriados sem ele.

Locks Python são específicos a CPython 3.13/Linux x86_64, com hashes de wheels. Para outra plataforma, revise `python scripts/lock_dependencies.py` e `--dev`, execute testes e atualize o ADR. Não remova verificação de hashes para contornar incompatibilidades sem uma resolução revisada. Node usa `npm ci` e lock de integridade.
