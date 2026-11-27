# Custódia externa — checkpoint #28/#117/#118

Sessão de 27/11/2026, limitada à #28 e suas duas subissues. Base examinada:
`4ee910c113f5b6e89d04519e99ed340d892ccaef`, `main`, árvore inicialmente limpa e
remoto no mesmo hash. Última mensagem da base:
`docs(retention): record integrated acceptance of snapshot retention (Refs #116, Refs #27)`.

## Resultado e bloqueadores

- **#117 aberta/adiada:** falta decisão explícita do responsável sobre destino,
  acesso, custódia independente da chave, retenção, RPO/RTO e condições do ensaio.
  A [preparação operacional](../operations/external-backup-custody.md) oferece
  alternativas sem contratação presumida, campos da decisão, origem confiável
  de hashes e procedimento de perda/recuperação. Nenhuma opção foi escolhida.
- **#118 aberta/bloqueada:** depende da #117 pelo corpo da issue e exige
  infraestrutura/destino novo e autorização específica do conjunto a transportar.
  Não foi iniciada transferência, guarda externa de chave ou recuperação externa.
- **#28 aberta:** pai adiado até decisão e ensaio externo com aceite conjunto.
  Não há evidência de proteção contra perda do host nesta sessão.

Consulta GitHub em 27/11: #28/#117/#118 abertas e sem comentários anteriores;
pai com filhos nativos #117/#118. Os três endpoints `dependencies/blocked_by`
retornaram listas vazias; isso não elimina os bloqueadores explícitos dos corpos.
Conector indisponível (`USER_NOT_LOGGED_IN`); leitura pelo `gh` autenticado.
Visibilidade observada pública, divergente de AGENTS.md; não alterada. Registrar
detalhes de destino, contas e custódia somente fora do repositório/issue públicos.

## Provas locais desta sessão

Comando executado na base, sem alteração de código/testes:

```sh
.venv/bin/pytest tests/test_backup_vault.py -q --tb=short
```

**21 passed, 1 warning in 1.57s**. Aviso existente de depreciação
Starlette/httpx. age/X25519 real sobre bytes sintéticos em arquivos temporários:
roundtrip fiel, chave/hash errados, corrupção/truncamento/extra, limites,
permissões/links/FIFO, corrida de substituição, publicação exclusiva e inventário
read-only. Nenhuma falha nessa execução. Não houve restore PostgreSQL nesta
suíte, Docker, acesso ao banco fonte ou prova de custódia independente.

Revisados AGENTS.md, session-workflow, corpos/comentários/dependências das três
issues, os dois runbooks indicados, ADR0016, Makefile, guia de testes e contratos
pertinentes de `vault.py`, `demo_backup.py` e `test_backup_vault.py`.
PROGRESS e chat antigo não foram usados. Alterações exclusivamente documentais;
sem implantação, build, conta nova, upload de dados, compra, geração de chave
operacional ou operação Linux/Wazuh/SIEM/originais. Backups e chaves de custódia
operacionais não foram abertos, modificados ou removidos. A suíte integral/CI
não foi usada como prova de validação desta preparação documental.

## Retomada e encerramento

Retomar somente após registrar a decisão completa da #117, em canal privado
para dados sensíveis. O pacote concreto da #118 deve delimitar conjunto,
destino, acesso, canais separados, janela, ações e cleanup antes da aprovação.
Pedido genérico de trabalho não supre esses requisitos. Hash/autenticação,
inventários, tempos e cleanup precisam de provas do ensaio realmente executado.

Checks de staged/release, commit final, mensagem e sincronização ficam registrados
nos comentários finais de #28/#117/#118. Nenhuma issue foi fechada por esta
preparação. Encerrar aqui, sem iniciar outra entrega ou o ensaio bloqueado.
