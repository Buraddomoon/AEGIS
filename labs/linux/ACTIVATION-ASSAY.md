# Ensaio de ativação — preparação da issue4

Estado em11/11/2026: **não executado nem autorizado**. O núcleo e a adaptação
nativa têm código/testes; a CLI separada `runner_rotation.py` exige pacote próprio
aprovado, evidência real da #48 e banco d446 compatível com os helpers fechados v3.
Esse perfil não inicia API normal/worker nem migra o original. Não invocar helpers de
lifecycle manualmente para contornar gates. O plano antigo `runner_activation.py`
continua somente plan/recheck, sem ampliar autorizações retroativamente. Nenhuma
autorização da issue3 é reaproveitável. Ver
[coordenador nativo](../../docs/operations/runner-native-rotation.md).

## Dependências, em ordem

1. #48: [compatibilidade a0/b7](../../docs/operations/linux-schema-compatibility.md).
   Backup frio do original, restore e upgrade d446→b7 no clone verificados.
   Original comprovado em d446/27tabelas; imagens e perfis devem respeitar isso.
   Conferir a evidência real no documento de compatibilidade.
2. #49: integração SQL/diário, núcleo e executor nativo com gates de
   runtime/mounts/lifecycle implementados/testados. Preparação do pacote operacional
   depende da prova real de clone da #48 e de schema/grants compatíveis no alvo.
   Não substituir gates por JSON ou chamar fixture de evidência física.
3. #50: registro transacional revogado, comparação da revisão sob lock, preflight
   sensível a mudança concorrente e fingerprints na UI implementados/testados.
   Binding real do Lab não foi modificado. Aprovações, scopes e provas preservados.
4. #51: casos de falha/cleanup e ciclo completo em fixtures disponíveis. Ensaio
   nativo depende dos três itens anteriores e de aprovação específica nova.

## O que o núcleo interno faz

Exige `ConfirmedPlan` válido e adapters de código confiável, sem CLI ou defaults
que abram os originais. Publica pedido exclusivo0600/fsync no diretório do plano
antes de preparar runtime. Esse fence inclui escopo, operação e prazo original;
presença parcial também impede nova tentativa. Retomada é somente cleanup.

Confere fonte/candidato, exige capacidade b7, integra duas leituras SQL com duas
revisões de diário, consulta identidade sem preparar/iniciar jobs e repete a
continuidade após o IO de identidade. Publica intenção de registro antes do commit.
Registro repete o predicado/provas sob lock, incrementa versão e mantém revogado.
Preflight atual é persistido separadamente; nova leitura completa aceita somente
mudança de descritor/versão e confere diário idêntico. Histórico não é reescrito.

O `finally` chama cleanup mesmo após interrupção/expiração. Cleanup só é aceito
com ausência confirmada pelo provider **e** intent fechado/todos os recursos
ABSENT. Ambiguidade no commit fica `binding_commit_state=unconfirmed`; não repetir
o registro ou desfazer binding confirmado para esconder a falha. Falha posterior
ao commit deixa o novo vínculo revogado. Cleanup incerto retém o intent aberto.

Recibo `aegis-internal-rotation-receipt/1` é diagnóstico do núcleo. Mesmo o status
`internal_rotation_reviewed_and_closed` mantém native_runtime_verified,
activation_verified e normal_operation_permitted **false**. TLS via fixture não
é mTLS nativo, e callback de fixture não verifica mounts/ownership/isolamento.
Os testes não são prova de ativação, implantação, detecção ou operação normal.

## Próxima intervenção proposta: somente clone da #48

Esta etapa foi autorizada pelo usuário nesta conversa e executada em11/11.
Uma execução não inclui rotação, registro, preflight real ou migração original.

Metadados lidos em11/11, sem abrir os volumes:

- fonte: `aegis-linux-lab_postgres-data`, driver local, labels projeto
  `aegis-linux-lab`/volume `postgres-data`, criação21/10/2026 11:08:45−03;
- diário preservado: `aegis-linux-lab_journal`, driver local, mesmos projeto e
  label `journal`, criação21/10/2026 09:39:53−03;
- nenhum consumidor dos dois volumes, inclusive parado, observado nessa leitura;
- PostgreSQL17 local Linux/amd64:
  `sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`.
  Presença/RepoDigest não substituem revisão de origem oficial antes de usá-lo.

Escopo autorizado e executado:

1. Revalidar projeto vazio, labels/consumidores, imagem PostgreSQL existente e
   proveniência. Fixar nonce, nomes/labels de helpers/clone e manifesto privado
   antes de qualquer create; colisão ou drift aborta sem adotar objetos existentes.
2. Copiar a frio **somente** PostgreSQL original, montado read-only/nocopy em
   helper network=none, para backup/clone novos identificados pelo nonce. Nunca
   iniciar PG sobre a fonte. Diário/PKI originais não são abertos por essa etapa.
   Dados permanecem no host, privados; nenhuma saída de conteúdo SQL/segredos.
3. Iniciar PostgreSQL17 somente sobre o clone, sem API/worker/runner/Wazuh ou rede
   externa. Conferir versão real e inventário; criar dump privado e restaurá-lo
   em segundo clone. O original continua parado e sem mount de escrita.
4. Aplicar somente a migração aditiva b7 no clone restaurado, sem seed/bootstrap,
   e verificar dados completos/ACLs e grants mínimos com credencial existente.
   Não rotacionar senha nem conceder privilégios no Demo ou original.
5. Encerrar/remover somente helpers/containers próprios, verificando IDs/labels
   e ausência. Preservar backup e volumes novos para revisão, além dos originais;
   não remover volumes, qasrc ou serviços alheios. Falha não concede retry.

A evidência desta intervenção está no documento de compatibilidade. Falhas de
preparação foram encerradas com cleanup; originais não foram remigrados. Preparar
o pacote próprio do executor nativo. Não aprovar implicitamente
etapas posteriores nem migrar o original para satisfazer os testes.

## Ensaio nativo de rotação posterior

O pacote deverá fixar fonte/candidato válidos, imagens por ID e fonte revisada,
schema/grants comprovados, nomes/labels/volumes exatos, endereços de rede sem
sobreposição, escopo/hash e prazo absoluto. Gate concreto verifica mounts de
secrets individuais/PKI, volumes, UID, isolamento e worker parado antes de cada
efeito. Um começo durável, sem renovação ou replay.

Evidência privada antes/depois: bundles SQL completos, inventários de diário,
descritor/versão do ambiente, identidade mTLS sob confiança nova, vínculo ainda
revogado, preflight atual, todas as fases/erros fechados e inventário final de
recursos. Publicar somente resumos/hashes, nunca dados/chaves/senhas/logs brutos.
Não converter EOF inconclusivo em recusa TLS comprovada; não reaproveitar recibo
histórico da #3 como conferência atual. Nenhuma campanha, start, marker ou SIEM.

Final bem-sucedido exige recursos próprios ausentes, volumes/PKI/journals/fences
preservados e limitações explícitas. Intenção pendente/cleanup incerto bloqueia
novo binding/ensaio e conserva dependências. Autorização de operação normal e
uma eventual campanha pertencem a escopos posteriores, não a este procedimento.
