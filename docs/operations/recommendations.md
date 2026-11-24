# Recomendações determinísticas — #22

A política `aegis-recommendations/1` analisa somente os fatos de uma execução
registrada. Não consulta sensores, usa LLM, inicia testes, altera regras ou muda
veredictos. Mesma entrada produz a mesma análise, sem relógio de geração.

Cada análise incorpora o documento da política e seu SHA256, hash da entrada,
identidade da execução, origem sintética, fatos por teste e vínculos de evidência
já registrados. O hash de integridade cobre toda a análise sem o próprio campo
`integrity_sha256`. Hash permite verificar alteração; não é assinatura.

| Ordem técnica | Condição registrada | Próximo passo |
|---|---|---|
| 10 | Cleanup falhou no pai ou filho | Recuperação segura; preservar journals/fences e confirmar limpeza |
| 20 | Execução falhou ou excedeu prazo | Inspecionar adaptador e comprovantes operacionais |
| 30 | Capacidade de coleta indisponível no resultado | Verificar acesso, configuração e disponibilidade da fonte |
| 40 | Janela de coleta não cumprida | Inspecionar janela, tempos e tentativas |
| 45 | Coleta incompleta | Inspecionar motivo e limites da fonte |
| 50 | Inconclusivo | Revisar justificativa, regra esperada e evidências ausentes |
| 60 | Observado sem alerta | Inspecionar eventos e regra/vínculo/versionamento registrados |
| 70 | Sem telemetria correlacionada suficiente | Verificar instrumentação e filtros de correlação |
| 80 | Sem avaliação | Conferir estado/escopo e aprovação própria antes de testar |
| 85 | Outcome desconhecido | Inspecionar contrato original, sem preencher contexto |
| 90 | Detectado | Inspecionar e conservar a prova limitada ao escopo |

Condições podem coexistir: detecção registrada não elimina falha de cleanup.
A ordem orienta investigação técnica; não representa severidade ou risco de
negócio. Campos ausentes permanecem desconhecidos. Eventos sem vínculo não viram
evidência associada; vínculo órfão indica ausência do evento e hash desconhecido.
Recibos do executor não entram na lista de evidências defensivas.

A saída é uma **análise nova e separada**, identificada pela política usada.
Não é a política histórica do veredicto. Alterações futuras da lógica exigem
versão nova; conservar o artefato original para reproduzir a análise anterior.
Não reescrever relatórios congelados ou históricos para incorporar recomendações.
Ausência de alerta não demonstra vulnerabilidade, comprometimento, ausência
física de eventos ou proteção empresarial. Nova execução, consulta externa,
recuperação e mudanças de regra dependem de escopo e autorização próprios.

## Verificação da política

```sh
.venv/bin/pytest tests/test_recommendations.py tests/test_domain.py -q --tb=short
.venv/bin/mypy
```

Os testes são fixtures offline: todos os outcomes, indisponibilidade, janela,
incompletude, falhas, ordem técnica, imutabilidade, hashes, origem e vínculos
órfãos. Não comprovam ensaio nativo ou implantação. A integração com detalhes e
exports pertence à subissue #101.
