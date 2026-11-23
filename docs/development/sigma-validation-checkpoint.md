# Validação Sigma em telemetria — #17

23/11/2026. Escopo #87 → #88 → #89. Dependências #16 e #7 CLOSED.
**SIGMA_NATIVE_QUERY_VERIFIED / CLEANED**: após autorização específica de consulta
e manutenção temporária da ACL, positiva1/negativa0 completas no Indexer real,
mapping físico conferido e role original restaurada. **Aceite conjunto atendido**,
CI final integral aprovada; conferir hashes/sincronização nos comentários finais.
Não repetir o ensaio.

- `66bf13d`: gate físico read-only, perfil keyword fechado; mapping/settings/
  aliases/versão e campos usados precisam coincidir com revisão prévia.
- `f8e20ee`: API administrativa de consulta gerada por versão/hash; escopo privado
  temporário, índice/agente/período fixos, limites, origem/completude e cleanup.
  Sem query livre, persistência/reclassificação histórica ou implantação de regra.
- `04e9c01`: probe de duas fases; `d2771a2` e `13ff3d8`: manutenção mínima da role,
  snapshot/reversão e operações suportadas pela API nativa. Não há CAS no servidor;
  o operador verifica isolamento de um escritor administrativo e GET antes/depois.
- 193testes locais pertinentes passaram com PostgreSQL/Redis15 em sequência;
  lint completo aprovado.6testes de registro histórico e checagem positiva/negativa
  sobre alerta salvo da #59 foram offline, sem executar Lucene/Indexer.
- CI anteriorf8e20ee44386130666 **SUCCESS**: quatro grupos Python3843passed/9skips
  existentes e115React, todos conferidos. CI anterior66bf13d também passou,
  com3809Python/9skips; não somar as duas rodadas. Demo anteriorb8 ativo preservado.
- Fonte nativa final13ff3d8:207testes locais pertinentes e lint aprovados.
  CI45192506887 **SUCCESS**:3857Python/9skips existentes e115React, quatro grupos
  Python e React conferidos; nenhum filtro/timeout relaxado.

[Provas, hashes, falhas intermediárias e limites](../evidence/sigma-validation-2026-11-18/README.md).
[Ensaio nativo e reversão](../evidence/sigma-validation-2026-11-18/VERIFIED-89.md).
[Aceite conjunto](../evidence/sigma-validation-2026-11-18/ACCEPTANCE-17.md).
[Contrato da API e plano da #89](../operations/sigma-query-validation.md).

Pacote finaleae8345c,23/11,14:17:25–14:17:59UTC. Quatro campos físicos usados,
alerta original da #59 idêntico;21requests nas validações, dois DELETEs confirmados.
Role antes/depois idêntica, zero recursos próprios/nove volumes sem consumidores.
PKI nova separada usada só no ensaio; originais/credenciais/IDs/qasrc/histórico
preservados. Tentativas anteriores INCONCLUSIVE/CLEANED retidas, sem reuso.
Sem novo marcador/run/veredicto ou implantação no Demo. Autorizações/pacotes
consumidos; sem operação contínua. **Parar após o aceite da #17**, sem outra entrega.
