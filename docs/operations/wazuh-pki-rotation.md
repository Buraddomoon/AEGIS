# Troca coordenada e rollback da PKI Wazuh

Entrega #6/#56, procedimento offline. **Nenhum comando deste documento concede
permissão de startup.** A #149 ainda bloqueia as redes e a #57 exige autorização
específica para o ensaio TLS. O ensaio de22/10 continua encerrado. Não reutilizar
seus intents, contas, bindings ou fences.

## Pacote revisável sem iniciar serviços

Primeiro conferir o [inventário/candidato](wazuh-pki.md). O comando abaixo cria
somente um plano privado e um overlay Compose; não chama Docker:

```bash
.venv/bin/python scripts/wazuh_pki_rotation.py prepare \
  --source /caminho/privado/wazuh-lab \
  --candidate /caminho/privado/wazuh-candidates/<id> \
  --candidate-sha256 <manifest_sha256> \
  --output-root /caminho/privado/wazuh-plans
.venv/bin/python scripts/wazuh_pki_rotation.py recheck \
  --plan /caminho/privado/wazuh-plans/<id> --expected-sha256 <plan_sha256>
make test-wazuh-pki-rotation
```

O pacote fixa candidato, origem, scripts, Compose base, hashes de credenciais,
política e identidades do runner. Somente o preparo de plano lê esses arquivos
privados de configuração; nenhum deles é copiado para o candidato ou impresso.
Não lê chaves antigas ou volumes. `lab.env` deve apontar exatamente para a origem,
runner, destino/IP e digests revisados; variáveis exportadas não podem substituí-lo.
Recheck exige integridade, pares, prazo restante, inputs intactos e overlay exato.
Hash é integridade, não assinatura/autorização nem prova de runtime.

`compose.pki.json` é um overlay YAML-compatible com **somente cinco** substituições
atômicas de seleção: CA pública, certificado/chave Indexer, certificado/chave
Filebeat. Todos apontam para o mesmo candidato. Não combinar CAs nem usar trust
antigo como fallback. Selecionar o overlay não troca os binds de containers já
criados: consumidores precisam de recriação explícita, sob escopo aprovado.

Os segredos continuam mounts RO individuais. Diretórios candidatos e CA privada
nunca são montados. API/worker recebem só a CA pública, política e reader; manager
recebe o par Filebeat e ingest; Indexer recebe seu par e CA. Agente/client.keys,
volumes, senhas, roles, imagens, redes, portas e PKI do runner não mudam.
`validate_rendered` compara em memória o Compose original/alterado e recusa
qualquer diferença além desses cinco arquivos; não publicar JSON renderizado,
pois contém credenciais. Os testes executam Compose real apenas em temporários,
sem daemon/startup, e conferem também o retorno aos caminhos originais.

## Pré-condições para a execução manual posterior

1. Resolver e aceitar #149; revisar SAN/IP/configuração e regenerar candidato/plano
   para o perfil aceito. Este perfil antigo é deliberadamente bloqueado. Não
   remover ou substituir qasrc, redes de terceiros ou volumes para fazê-lo passar.
2. Ter preflight atual aprovado:8GiB MemAvailable,4CPUs,50GiB livres no Docker,
   vm.max_map_count>=262144 e imagem/digest/arquitetura previstos. Não alterar
   sysctl, parar outros projetos ou baixar/buildar imagens por este procedimento.
3. Revisar IDs/labels reais dos containers/redes/volumes exclusivos de
   `aegis-wazuh-lab`, mounts, consumidores e ausência de endpoints SIEM publicados.
   API, se aprovada, só127.0.0.1:18786;9200/1514/1515/55000 não são publicados.
   Alterações nos metadados ou consumidores novos bloqueiam a operação.
4. Confirmar ausência de campanha/job/cleanup pendente; laboratório permanece
   revogado e sem execução de marcador. A recuperação do original tem precedência
   sobre qualquer troca. Não abrir/migrar o banco para satisfazer uma checagem.
5. Apresentar ao usuário plano/hash atuais, IDs, volumes, serviços, comandos,
   janela e cleanup. Obter autorização específica de startup/leitura/TLS da #57.
   Nenhuma saída `verified` ou flag de confirmação substitui essa autorização.

## Ordem e evidência por etapa

Manter dois conjuntos Compose revisados, com o mesmo projeto, arquivos base e
`--env-file` protegido: **original** e **candidato**, este acrescentando somente
`-f <plano>/compose.pki.json`. Sanitizar variáveis Compose/Docker/SIEM herdadas,
usando o daemon Unix local. Não usar `make wazuh-lab-up`: ele inicia a campanha
completa e não representa o escopo TLS restrito.

Antes de cada efeito, registrar INTENT exclusivo/durável/fsync em um diretório
0700 novo vinculado ao hash do plano. Depois, registrar confirmação com digest da
observação real protegida, incluindo UTC/IDs/mounts. Não registrar conteúdo de
segredos. `ProcedureJournal` implementa a sequência e hashchain, sem executar
Docker ou aceitar provas de runtime por CLI. Seus testes usam observações
fictícias; um hash informado ao diário não transforma uma fixture em evidência.

| Etapa | Efeito explícito e condição de avanço |
|---|---|
| Quiescer consumidores | Parar worker/API, agente e manager pelo Compose original, sem iniciar dependências; conferir parada real de cada consumidor |
| Parar Indexer | Parada explícita do Indexer original; reconferir que nenhum consumidor está ativo, nem em outro projeto |
| Indexer candidato | `up -d --no-deps --no-build --pull never --force-recreate wazuh.indexer` com overlay; preservar `indexer-data` e security index; conferir ID/imagem/mounts/limites e CA/SAN/SNI/DN/TLS reais |
| Manager/Filebeat candidato | Mesmo comando limitado a `wazuh.manager`, só após TLS do Indexer aprovado; preservar etc/logs/queue; comprovar `filebeat test output` com verificação `full` e identidade do servidor |
| Agente | Iniciar/recriar somente `wazuh.agent` com `--no-deps --no-build --pull never`; confirmar001/aegis-marker Active e client.keys preservado, sem enrollment novo; observador/runner não são iniciados |
| Coletor/ACL | Verificação restrita conforme #57: reader, CA/SNI/destino fixo, leitura de alertas e negativas de ACL. Não iniciar API/worker/banco/migração implicitamente para executar essa leitura |
| Encerrar | Parar todos os consumidores candidatos iniciados, incluindo o Indexer; confirmar ausência de consumidores ativos; preservar relatório, plano, diário, configurações e todos os volumes |

Cada efeito pode ser ambíguo mesmo se o processo retornar erro. Não repetir `up`,
recriar IDs ou saltar etapas após timeout/interrupção. O diário recarregado mantém
INTENT pendente; prova de reconciliação e revisão são necessárias antes de entrar
na sequência de rollback. Erro parcial/fsync/cadeia inválida retém artefatos e
impede aceite. Não apagar o evento para reiniciar. Cleanup não depende de memória
suficiente para startup e não executa `down -v`, prune, remoção de volumes ou logs.

## Rollback seguro e conclusão

Rollback não é restaurar o banco nem misturar trust. Registrar a decisão e a
reconciliação de efeitos pendentes, parar todos os consumidores candidatos e
confirmar parada real. Selecionar de novo **todos** os arquivos Compose originais,
sem overlay; conferir os cinco caminhos antigos e hashes de configuração/segredos,
IDs e volumes preservados. Deixar os serviços **parados**. Como os certificados
antigos expiraram, esse rollback restaura a configuração, não a disponibilidade;
não iniciar com certificados expirados ou TLS desativado. Não há restart automático.

Se cleanup não puder ser comprovado, manter estado pendente/quarentena, conservar
acesso à recuperação original e evidências; não declarar conclusão nem apagar
containers/volumes para ocultar falha. Depois de cleanup comprovado, encerrar a
operação de uso único, manter candidato/plano/diário históricos e registrar
implementado/testado por fixture/ensaiado separadamente. Nenhum resultado desta
preparação comprova coleta real, alerta defensivo ou eficácia do Wazuh.
