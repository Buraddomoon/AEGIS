# Retenção de histórico — #27

A unidade desta política é um snapshot completo. Eventos, evidências, auditoria,
recibos, relatórios e contexto (escopos, aprovações, versões, contas e relações)
permanecem juntos no dump PostgreSQL. Nenhuma tabela recebe TTL ou DELETE; não
há alteração de triggers append-only, grants, migrações ou endpoints web.

A área host-only de retenção recebe **cópias explicitamente cadastradas** de
backups. Originais, arquivos cifrados, chaves, journals e fences não são alvos.
Aplicar significa remover apenas uma cópia em claro cadastrada nessa área,
após arquivo cifrado e restauração isolada confirmados. Isso reduz o espaço das
cópias em claro; não reduz tabelas do banco nem promete retenção off-host.

A política JSON precisa ser fornecida explicitamente:

```json
{
  "format": "aegis-history-retention-policy/1",
  "retain_days": 30,
  "minimum_snapshots": 7,
  "legal_holds": []
}
```

Trinta dias e sete snapshots **distintos e verificados** são pisos herdados do
planejador anterior, não autorização para excluir. É possível aumentá-los. Um
hold contém o ID exato do backup, sem justificativa confidencial no plano. Dados
incompletos, formato desconhecido e cópia sem restauração verificada ficam
preservados. Duas cópias/IDs do mesmo inventário não contam duas vezes para o
mínimo. Uma cópia recente e qualquer hold são preservados independentemente do
mínimo. Nenhuma política é executada automaticamente no startup/worker/CI.

O plano inclui membros e hashes de arquivos, contagens por categoria/tabela,
bytes reais de arquivos, motivos, política, área, validade de até uma hora e hash
do conjunto. Tamanho de linhas não é estimado: aparece como desconhecido.
Mudanças de política, hold, arquivos, recibos ou conjunto exigem outro plano.
Hashes não são assinatura; recibo local não comprova custódia independente.

Uso destrutivo no ambiente humano exige nova aprovação específica do pacote e
é proibido na sessão de implementação da #116. Testes usam recursos descartáveis.
A fonte em10/11 tinha somente planos consultivos de backups; este documento não
reescreve essa evidência histórica nem altera os comandos consultivos existentes.
