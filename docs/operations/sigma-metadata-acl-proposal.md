# ACL temporária para a #17 — plano autorizado, ainda não aplicado

23/11/2026. A tentativa autorizada da #89 chegou ao Indexer real, confirmou TLS e
o principal `aegis_reader`, mas recebeu HTTP403 em
`GET /wazuh-alerts-4.x-2026.11.16/_mapping`. As consultas Sigma não foram executadas.
[Provas e encerramento](../evidence/sigma-validation-2026-11-18/NATIVE-ATTEMPTS.md).

O escopo registrado antes dos efeitos vedava alterar mapping/ACL para passar.
Esta proposta é uma operação administrativa adicional. Em23/11, após apresentação
do ajuste e da reversão, o usuário escolheu explicitamente **“Autorizar ajuste mínimo
e reversão”**, incluindo PKI temporária válida e preservação dos originais.
A autorização de consulta anterior não foi usada para ampliar privilégios.
Até a preparação deste plano, nenhuma chamada administrativa ou alteração de role,
senha, conta, mapping, documento ou configuração original havia sido feita.

## Alteração proposta

Usar o administrador existente apenas para ler e atualizar a role `aegis_reader`
pela API Security, com TLS/CA/SNI/IP/fingerprint verificados. Acrescentar uma entrada
de permissão para **um índice concreto**, preservando as entradas atuais:

```json
[
  {
    "op": "add",
    "path": "/index_permissions/-",
    "value": {
      "index_patterns": ["wazuh-alerts-4.x-2026.11.16"],
      "allowed_actions": [
        "indices:admin/mappings/get",
        "indices:monitor/settings/get",
        "indices:admin/aliases/get"
      ]
    }
  }
]
```

Destino único: `PATCH /_plugins/_security/api/roles/aegis_reader`. O JSON acima é o
acréscimo revisável; antes do PATCH efetivo, inserir uma precondição `test` do
`index_permissions` observado no GET autenticado da mesma role. Não adivinhar a
representação ativa a partir do arquivo YAML. Rejeitar drift, privilégio adicional
inesperado, role reservada ou resposta ambígua, preservando o snapshot host-only.
Não conceder `manage`, wildcard administrativo, acesso à API Security para o reader
ou permissão de escrita de documentos.

As três ações são permissões de leitura de metadata, segundo a
[referência oficial OpenSearch](https://docs.opensearch.org/latest/security/access-control/permissions/).
A permissão de aliases é também descrita no
[GET Alias](https://docs.opensearch.org/latest/api-reference/alias/get-alias/).
O403 observado comprova a negativa do mapping; settings/aliases ainda não foram
consultados e sua disponibilidade não é presumida. A confirmação dessas ações na
versão nativa faz parte do ensaio posterior; não ampliar a lista automaticamente.

## Execução e reversão propostas

1. Preparar pacote/intent novos, fixar imagens e rede isolada já documentadas na
   #89 e repetir preflight de recursos/consumidores. Pacotes anteriores permanecem
   encerrados. Usar PKI temporária válida separada, mantendo todos os originais.
   O leaf de18/11 expirou em19/11; a CA antiga vence23/11 às19:50:08UTC. Se for
   necessário gerar nova CA/certificados de ensaio, a seleção deve constar do novo
   pacote e ser limitada ao Indexer/leitores temporários, sem atualizar consumidores
   ou arquivos originais. Não aceitar certificado expirado ou desabilitar TLS.
2. Salvar a role ativa e seu hash antes da mudança; registrar INTENT da manutenção.
   Aplicar somente o acréscimo acima com a precondição exata. Sem retry automático
   após resposta perdida: reler/reconciliar o estado antes de qualquer ação.
3. Conferir por GET a role resultante exata. Usando somente o reader, comprovar
   leitura de mapping/settings/aliases e manter as negativas de Security. Se os
   campos físicos forem incompatíveis, encerrar sem modificar o índice.
4. Executar somente as duas consultas geradas e revisadas da #89 sobre o alerta
   preservado da #59, com as versões/hashes e o período fixados no pacote novo.
   Preservar resultado positivo/negativo, completude, origem e limpeza de cursores.
5. Em sucesso, falha ou cancelamento, remover exclusivamente a entrada acrescentada,
   com precondição que confirme o estado temporário exato. Conferir igualdade da
   role final com o snapshot inicial, sem sobrescrever mudanças de terceiros.
   Reversão incerta exige reconciliação; não declarar restaurado por um404.
6. Parar/remover apenas os recursos próprios; conferir zero consumidores dos nove
   volumes retidos. Guardar snapshots, intenções, respostas e certificados host-only.
   Nenhuma operação normal, marcador/run, ingestão, migração ou implantação de regra.

A manutenção escreve a configuração Security no volume Indexer original. A
reversão restaura a política, mas não torna a operação fisicamente read-only nem
apaga os registros administrativos. A autorização específica recebida vale para
essa manutenção temporária e sua reversão no ensaio limitado; não concede
operação contínua nem reuso de pacotes.
