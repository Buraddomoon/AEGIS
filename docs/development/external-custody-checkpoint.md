# Custódia externa — checkpoint #28/#117/#118

Estado final: [aceite do perfil manual em 27/11/2026](../evidence/external-custody-2026-11-27/ACCEPTANCE-28.md).
Registros abaixo preservam as etapas e os bloqueios anteriores. O responsável
confirmou a guarda após receber o conjunto atual e a instrução de separar a
chave; execução final dos ZIPs exatos restaurou 33 tabelas/3.399 linhas em destino
novo, sem fallback ou alteração do Demo. Confirmação externa é do responsável;
sem auditoria da nuvem ou download de retorno verificado pelo agente.

Sessão de 27/11/2026, limitada à #28 e suas duas subissues. Base examinada:
`4ee910c113f5b6e89d04519e99ed340d892ccaef`, `main`, árvore inicialmente limpa e
remoto no mesmo hash. Última mensagem da base:
`docs(retention): record integrated acceptance of snapshot retention (Refs #116, Refs #27)`.

## Resultado inicial e bloqueadores

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

## Retomada após transporte manual informado

Ainda em 27/11, após explicação do objetivo, o responsável informou:
“backup-vault guardado em nuvem,pode continuar”. Isso registra escolha de
transporte manual para nuvem e relato de cópia realizada pelo próprio usuário;
o agente não acessou o provedor nem verificou seus bytes/ACLs. Nenhum endereço,
conta, caminho privado de custódia ou hash do backup humano é publicado aqui.

A inspeção local de metadados encontrou no checkout histórico uma cópia cifrada
de 26/10/2026, 1.318.864 bytes. Seu SHA256 corresponde ao envelope e ao recibo
histórico `decrypted_and_restore_verified` de 26/10. Isso confirma integridade
local e vínculo com registro anterior, não uma nova decriptação/recuperação ou
a integridade da cópia na nuvem. Há uma identidade privada local; seu conteúdo
não foi lido nessa inspeção. A imagem PostgreSQL17 local e pyrage1.4.0 estão
disponíveis, sem pull/build/start.

Validação complementar já executada na retomada:

```sh
.venv/bin/pytest tests/test_backup_cli.py -k sealed -q --tb=short
```

**5 passed, 62 deselected, 1 warning in 0.08s**. Seleção dos contratos de cópia
cifrada: uso exclusivo do staging autenticado, origem em claro indisponível,
recusa de adulteração, falhas de restore/cleanup e publicação do recibo somente
após cleanup. age real/arquivos sintéticos; Docker/restore substituídos por
fixtures. Aviso existente Starlette/httpx; nenhuma falha. Não é nova CI integral.

Solicitado ao responsável confirmar custódia da chave em local separado e
baixar novamente a cópia da nuvem para pasta nova, informando o caminho para
comparação e teste. Sem esse retorno, o agente só dispõe do arquivo local
original. Retenção, acesso e metas de perda/tempo de recuperação continuam sem
decisão explícita. #117/#118/#28 permanecem abertas, sem aceite conjunto.

## Verificação nativa local dos ZIPs informados

O usuário confirmou ter guardado também o ZIP da chave, mas no mesmo lugar da
cópia. Confirmou que o ZIP local é o arquivo enviado, não um download de retorno.
Logo, a guarda externa é relato do responsável e a separação de custódia/canal
ainda não foi atendida. Não converter esse envio conjunto em prova de separação.

Em 27/11, 20:24:47–20:24:52 UTC, a orquestração host-only em
`.venv/bin/python` chamou o fluxo real `scripts/demo_backup.py::verify_sealed`
sobre os ZIPs locais conhecidos, com SHA256 esperado vindo da referência local
anterior. ZIPs foram lidos sem extração genérica: apenas `bundle.age`,
`envelope.json` e a identidade específica foram materializados em diretórios
novos 0700/arquivos0600. Rejeição de paths inseguros/links, nomes duplicados e
limites aplicada antes do uso. Fonte em claro e banco fonte foram explicitamente
indisponibilizados para impedir fallback. Funções de decriptação, restore,
inventário e cleanup foram reais, sem substituir Docker/PostgreSQL por fixtures.

**`decrypted_and_restore_verified`**, 32 tabelas/3.169 linhas, inventários de
dados/estrutura iguais ao snapshot de 26/10. Restore medido em 5,29s; operação
local total 5,368s. Clone novo PostgreSQL17 por ID, sem rede/portas/volumes
persistentes, somente tmpfs; sem aplicação/worker/SIEM. Recibo publicado após
cleanup; staging decriptado e cópia temporária da chave removidos. ZIPs fontes
byte a byte iguais antes/depois. Consulta posterior do nome próprio confirmou
ausência do único clone criado. Não foi criado snapshot atual ou alterado o Demo.

Referência opaca do conjunto privado de recibo/intents/summary:
`custody-local-zip/2026-11-27/8bc74e0e33664bb29761a8b784b1a942`.
Não publicar os ZIPs, chave, hashes humanos ou caminhos privados na issue.
O teste valida recuperabilidade local do pacote enviado. Não comprova bytes/ACLs
da nuvem, canal separado da chave, perda do host, outro computador ou RPO/RTO.
Solicitado download para arquivo novo e escolha de guarda separada da chave.

## Cópia atual preparada e verificada

O responsável manifestou intenção de guardar a chave separadamente. Informou
“pronto” para o download, porém nenhum arquivo de retorno foi encontrado no
caminho solicitado nem nos diretórios de backup/Downloads consultados; o único
ZIP identificado continuava sendo o original enviado. Ao pedir esclarecimento
do caminho, o usuário pediu seguir e aceitou o risco de perda. Esse aceite foi
respeitado sem novas perguntas; não foi convertido em evidência de download,
ACL, segregação já efetivada, retenção ou metas numéricas de recuperação.

Para preparar um conjunto atual completo e revisável, foi usado o fluxo real
`scripts/demo_backup.py::backup` → `seal_backup` → `verify_sealed`, por
orquestração host-only em `.venv/bin/python`, sem alteração dessas funções.
Configuração existente usada somente no processo, sem imprimir credenciais.
Fonte restrita ao único DB do Demo padrão já ativo; URL/cluster/imagem conferidos
pelas guardas existentes. Transação REPEATABLE READ/READ ONLY e snapshot exportado
compartilhado com pg_dump, sem migração, DDL, mudança de grants ou operação Lab.

Snapshot de **27/11/2026, 20:28:00 UTC**, 33 tabelas/3.399 linhas. Identidade age
nova e cifra reais, 1.340.002 bytes de ciphertext. Restore completo em clone
PostgreSQL17 local por ID, sem rede/portas/volumes persistentes, inventários
iguais, **`decrypted_and_restore_verified`**, 5,802s de restore. Clone e staging
removidos antes do recibo; consulta posterior do nome próprio confirmou ausência
do único clone criado. Sem boot de aplicação, Redis, worker, cutover ou Lab.
Backup novo e arquivos históricos preservados. Não é SLA ou RPO/RTO medido.

Referência opaca dos recibos/manifesto/envelope/summary privados:
`custody-current/2026-11-27/66285a1dc03c4967999df6f834554ff9`.
Pacote de entrega privado: ZIP de 1.341.456 bytes contendo somente ciphertext,
envelope e instruções; nenhuma chave ou dump em claro. ZIP da identidade nova
preparado em outro diretório privado, 569 bytes; ZIP não cifra a chave. Referência
de SHA256 preparada separadamente. Arquivos0600 e diretórios0700; criação
exclusiva/fsync e CRC dos ZIPs conferidos. Nenhum artefato privado incluído no Git.

O novo conjunto exige usar sua própria chave, preservando a antiga para o
snapshot anterior. O agente não o enviou à nuvem; entrega externa e guarda
separada continuam a cargo do responsável. #117/#118/#28 permanecem abertas:
faltam decisões explícitas de acesso/retenção/RPO/RTO e prova externa completa.
Aceitação pessoal de risco não reescreve o envio conjunto histórico nem substitui
os critérios pendentes. Encerrar o trabalho executável nesta máquina sem nova
pergunta, novos envios, replays ou entrega fora da #28.

## Condições registradas antes da confirmação final

Registrar a decisão completa da #117, em canal privado
para dados sensíveis. O pacote concreto da #118 deve delimitar conjunto,
destino, acesso, canais separados, janela, ações e cleanup antes da aprovação.
Pedido genérico de trabalho não supre esses requisitos. Hash/autenticação,
inventários, tempos e cleanup precisam de provas do ensaio realmente executado.

Checks de staged/release, commit final, mensagem e sincronização ficam registrados
nos comentários finais de #28/#117/#118. Nenhuma issue foi fechada por esta
preparação. Encerrar aqui, sem iniciar outra entrega ou o ensaio bloqueado.

## Aceite final do fluxo manual

Após a entrega dos três artefatos atuais, preservados em caminhos privados
separados, o responsável respondeu “pronto” e reiterou concluir a issue. Isso
confirma o atendimento manual às instruções recebidas, incluindo guarda da
identidade nova separadamente. Não é declaração de auditoria feita pelo agente.
Política adotada sob a delegação e aceitação do risco: destino/acesso operados
pelo responsável, preservação integral sem exclusão e recuperação manual em
melhor esforço, sem promessa de frequência/RPO/RTO máximos.

Para fechar a parte técnica do conjunto entregue, o agente conferiu hash do ZIP
contra a referência separada e executou decriptação/restore reais somente dos
dois ZIPs atuais em destino novo, sem acesso a backups em claro ou banco fonte:
**`decrypted_and_restore_verified`**, 33 tabelas/3.399 linhas, inventários iguais,
restore 5,983s/total 6,09s, cleanup confirmado e pós-consulta do clone ausente.
Staging e cópia temporária da chave removidos; dois ZIPs e referência inalterados.
Referência privada `custody-transport/2026-11-27/e7d79c2448b64dfc80e214dd017ed150`.

O [aceite conjunto](../evidence/external-custody-2026-11-27/ACCEPTANCE-28.md)
explicita evidências e limites de cada critério, inclusive ausência de auditoria
remota. Encerrar filhos #117/#118 e então #28 com comentário de provas, commit
e sincronização; parar nesse escopo. Não reabrir aprovação/ensaio/ambiente Lab.
