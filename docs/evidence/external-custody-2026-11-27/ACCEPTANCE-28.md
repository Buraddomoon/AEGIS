# Aceite #28 — custódia externa manual

Data: 27/11/2026. Escopo: #28 e filhos #117/#118, somente os dados do Demo.
Perfil entregue: transporte e custódia manuais pelo responsável, com pacote
cifrado e recuperação nativa dos ZIPs exatos em destino novo isolado.

## Decisão e origem da evidência

O responsável informou ter guardado a cópia histórica em nuvem e a chave;
inicialmente informou ambas no mesmo local. Essa situação anterior permanece
registrada no [checkpoint](../../development/external-custody-checkpoint.md).
Depois manifestou intenção de guardar a chave separadamente, aceitou o risco
de perda e pediu ao agente que prosseguisse. Um conjunto atual com chave nova
foi então preparado e entregue por caminhos separados, junto da referência de
integridade. Após receber esses arquivos e instruções, respondeu “pronto” e
reiterou a conclusão da issue. Essa resposta é a confirmação do responsável
sobre a guarda manual do conjunto atual conforme a entrega.

A prova da guarda externa e da separação é **a confirmação do responsável**.
O agente não acessou a conta de nuvem, verificou ACLs remotas ou recebeu um
download de retorno identificável. A prova de hash, decriptação, inventário,
restore e cleanup é **a execução nativa local** descrita abaixo. Não apresentar
uma fonte de evidência como se fosse a outra. O aceite é do fluxo manual; não
é auditoria independente do provedor nem recuperação demonstrada em outro host.

## Política registrada — #117

Escolhas operacionais conservadoras adotadas sob a delegação de concluir a
entrega e a aceitação de risco pelo responsável, sem contratação, exclusão ou
transferência adicional pelo agente:

| Item | Decisão do perfil manual |
| --- | --- |
| Destino | Nuvem já escolhida e operada pelo responsável; detalhes de conta/local ficam sob seu controle e fora do Git/issue |
| Acesso | Responsável controla credenciais, leitura, transporte e recuperação de acesso; o agente não recebe credenciais nem cria acesso externo; controle remoto não auditado |
| Custódia da chave atual | Pacote próprio com identidade nova, entregue separadamente; guarda separada confirmada pelo responsável após as instruções |
| Referência confiável | Registro SHA256 separado, calculado antes da entrega; ZIP e bundle conferidos contra essa referência |
| Retenção | Preservar todas as cópias e respectivas chaves até nova decisão explícita; sem exclusão automática ou destrutiva autorizada |
| RPO | Recuperação até o snapshot manual de 27/11, 20:28:00 UTC; perda posterior até outra cópia manual assumida pelo responsável, sem intervalo máximo garantido |
| RTO | Recuperação sob demanda em melhor esforço, sem prazo máximo/SLA contratado; medição do restore local não é tempo garantido de recuperação externa |
| Frequência | Manual, sem agendamento ou promessa de backup contínuo |
| Perda/recuperação | Obter cópia, identidade e referência em custódias independentes; usar checkout/imagem compatíveis, autenticar e restaurar em destino isolado antes de qualquer retomada |

RPO/RTO sem limite garantido são limites deliberados deste perfil sob aceitação
de risco, não metas numéricas inventadas. Esse aceite não adiciona automação,
monitoramento remoto, garantia de durabilidade ou autorização de apagar dados.

## Recuperação nativa do pacote final — #118

Conjunto autorizado: somente o ZIP cifrado atual, seu envelope, ZIP separado
da nova identidade e referência de integridade. Nenhum dump em claro, `.env`,
imagem, PKI ou journal integra o ZIP de transporte. Originais e chaves antigas
preservados. Transporte externo foi realizado pelo responsável, não pelo agente.

Execução em 27/11, **20:36:07–20:36:14 UTC**, após a confirmação final do usuário.
Orquestração host-only `.venv/bin/python` chamou a função existente
`scripts/demo_backup.py::verify_sealed` sobre material obtido dos dois ZIPs
atuais, com código de produção preservado:

1. Conferiu SHA256 do ZIP contra o registro confiável separado e SHA256 do bundle
   contra a referência anterior à entrega. ZIP da cópia sem identidade privada.
2. Leu apenas os nomes fixos esperados, com limites e recusa de links, traversal
   e duplicados; sem extração genérica. Diretórios novos 0700 e arquivos0600.
3. Obteve a identidade somente do ZIP separado, em cópia temporária privada.
   Banco fonte e backups em claro indisponibilizados como fallback.
4. Autenticou todo o stream age antes do restore real em clone PostgreSQL17
   novo por ID imutável local, `network=none`, sem portas/volumes persistentes,
   somente tmpfs, sem API/worker/Redis/SIEM.
5. Comparou inventários de dados/estrutura: **33 tabelas e 3.399 linhas iguais**.
   Resultado **`decrypted_and_restore_verified`**, restore5,983s, total6,09s.
6. Confirmou cleanup antes do recibo; consulta posterior confirmou ausência do
   clone próprio. Staging decriptado e identidade temporária removidos. ZIPs e
   referência byte a byte iguais antes/depois. Sem alteração do Demo em uso.

Recibo/intents/summary privados, referência opaca:
`custody-transport/2026-11-27/e7d79c2448b64dfc80e214dd017ed150`.
Nenhum segredo, endereço de custódia ou hash humano publicado neste documento.

As verificações anteriores do snapshot histórico e do snapshot atual permanecem
no checkpoint, com seus resultados próprios. Esta execução final valida o
formato exato entregue; não é repetição de campanha nem efeito de laboratório.

## Aceite conjunto e limites

| Critério | Evidência |
| --- | --- |
| Destino/acesso/retenção/RPO/RTO | Política manual acima, risco aceito e custódia operada pelo responsável |
| Cópia externa e chave separada | Confirmação do responsável após entrega atual e instrução de separação; sem auditoria remota pelo agente |
| Hash/autenticação/restore | ZIP e bundle contra referência independente; age e PostgreSQL reais, inventários iguais em destino vazio |
| Preservação e cleanup | Originais idênticos, histórico/chaves antigas retidos, clone e temporários removidos |
| Evidência e sincronização | Checkpoint/runbook/este aceite; checks, commits e estado remoto nos comentários finais das três issues |

Não há promessa de disponibilidade do provedor, recuperação de configuração,
roles globais, imagens, Redis, PKI, journals ou efeitos externos. Restore de
dados não autoriza cutover, migração, operação Linux/Wazuh/SIEM ou replay.
Sem implantação ou CI integral nova alegada. Problemas e limites anteriores não
foram apagados. Aceite limitado ao perfil manual descrito; encerrar #117/#118
antes do pai #28 e parar, sem iniciar outra entrega.
