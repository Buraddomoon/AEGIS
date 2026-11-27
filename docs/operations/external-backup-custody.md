# Custódia externa — decisão pendente #28/#117

Estado atualizado em 27/11/2026: o responsável informou ter guardado manualmente
o `backup-vault` histórico em nuvem e pediu continuidade. **Envio informado pelo
responsável; cópia remota ainda não verificada pelo agente.** A cópia identificada
é de 26/10/2026 e não representa os dados atuais. Custódia independente da chave,
acesso, retenção, RPO/RTO e teste de recuperação ainda precisam ser confirmados.
O relato de envio não comprova integridade remota ou restore.

Complemento: o usuário informou ter guardado também a chave **no mesmo lugar**
do backup. Isso não atende à separação de custódia/canal exigida pela #118. O
ZIP local enviado passou por decriptação e restore reais em clone descartável,
32 tabelas/3.169 linhas, cleanup confirmado; ele não foi baixado de volta da
nuvem. A verificação remota continua pendente. Recibos e limites estão no
[checkpoint](../development/external-custody-checkpoint.md).

Depois, o responsável manifestou intenção de guardar a chave separadamente,
aceitou o risco de perda e pediu continuidade. Uma cópia **atual de 27/11/2026**
foi criada do Demo ativo em snapshot somente leitura, cifrada com identidade
nova e restaurada/verificada: 33 tabelas/3.399 linhas, cleanup confirmado. ZIPs
privados de cópia e chave foram preparados em diretórios separados, além de
referência de hashes. Esse novo conjunto ainda não teve transporte externo
informado ou verificado. Preservar o conjunto histórico e sua chave anterior.

Reutilizar [cifragem age/X25519](encrypted-backups.md) e
[recuperação em quarentena](backup-recovery.md), conforme o
[ADR0016](../architecture/decisions/0016-encrypted-demo-backups.md).
Não há novo upload, agendamento, provedor ou endpoint de restore.

## Alternativas para o responsável avaliar

O responsável escolheu transporte manual para armazenamento em nuvem que já
utiliza; provedor/conta e detalhes de acesso não foram informados. As alternativas
abaixo preservam o contexto da decisão. Não criar contas, contratar serviços ou
presumir armazenamento gratuito.

| Alternativa | Condição para independência do computador | Limitação a decidir |
| --- | --- | --- |
| Mídia removível já disponível, guardada em outro local | Desconectada e fora do local do host; chave em outra custódia | Transporte, frequência, perda física e acesso durante incidente |
| Segundo computador ou armazenamento já administrado pelo responsável | Outro local e acesso recuperável sem depender do host perdido | Disponibilidade, manutenção e exposição por credenciais compartilhadas |
| Armazenamento remoto escolhido pelo responsável | Conta e recuperação de acesso independentes do host; canal autenticado | Termos, capacidade, custos, retenção e recuperação de conta |

Outra pasta, volume, tag de imagem ou disco no mesmo computador não resolve
perda do host. Mesmo um destino externo fica vulnerável se sua única credencial
de acesso ou a única identidade age permanecer no computador perdido.

## Registro da decisão #117

Preencher primeiro em registro privado controlado pelo responsável. Publicar na
issue somente referência opaca, estado e decisões não sensíveis. Este repositório
está público na consulta desta sessão, divergindo da política privada de
AGENTS.md; não alterar visibilidade nem publicar endereços, contas, caminhos de
custódia, identidades, tokens ou hashes de arquivos humanos. Exemplos abaixo
são campos pendentes, sem valores operacionais predefinidos.

| Campo obrigatório | O que registrar privadamente |
| --- | --- |
| Responsável e substituto | Quem aprova, transporta e recupera; quem pode agir se o titular estiver indisponível |
| Destino da cópia | Recurso exato, proprietário, local independente e capacidade confirmada |
| Acesso ao destino | Quem lê/escreve/remove, autenticação e recuperação de acesso sem o host original |
| Custódia da identidade age | Dispositivo/local independente da cópia, custodiante e canal separado; referência à chave, nunca seu conteúdo |
| Referência confiável | Registro independente que vincula ID, SHA256 do ciphertext, destinatário público, origem e instante do snapshot |
| Conjunto permitido | IDs, tamanhos, arquivos exatos e exclusões; política separada para configuração, imagens, PKI e journals |
| Retenção | Duração, número de snapshots distintos, holds e tratamento de cópias antigas/chaves; sem autorizar exclusão nesta entrega |
| RPO | Perda máxima aceitável em tempo, frequência de snapshot/transporte e como detectar atraso |
| RTO | Tempo máximo desejado, marco inicial do incidente e marco final: dados verificados, API em quarentena ou serviço recuperado |
| Ensaio #118 | Destino novo isolado, recursos/imagens compatíveis, janela/validade, operador, canais, ações permitidas e cleanup |
| Aprovação | Referência, data e aceite explícito do responsável sobre esses valores e o conjunto do ensaio |

RPO é objetivo de perda tolerada, não a idade de qualquer arquivo disponível.
Medir no ensaio a diferença entre o instante de referência do incidente e o
snapshot recuperável mais recente efetivamente disponível fora do host.
RTO exige início/fim definidos e inclui obter credenciais, chave, código e
imagens, transportar, verificar e limpar. Uma duração de decriptação local não
demonstra esse tempo. Se o marco for serviço operacional, restore de dados ou
boot em quarentena não o satisfaz. Valores ausentes continuam **não definidos**.

A política local do vault mantém sete snapshots distintos verificados com chave
local e todos com até 30 dias, apenas como plano. Isso não escolhe retenção
externa nem permite descartar chaves ou substituir cópias boas por não verificadas.
Chaves antigas continuam necessárias para suas cópias antigas.

## Preparação e ensaio #118, somente após aprovação

1. Revisar o registro privado completo e a autorização vigente do conjunto exato.
   Conferir origem confiável, schema/manifesto e imagens por ID imutável. O bundle
   Demo contém manifesto/dump, sem roles globais, configuração, segredos, Redis,
   PKI, imagens ou journals. Não tratá-lo como recuperação completa de Linux/Wazuh.
   Incluir outro material exige procedimento e escopo próprios aprovados.
2. Usar uma cópia selada pelo fluxo existente. Conferir o SHA256 com a referência
   confiável independente, não apenas com o envelope que acompanha o arquivo.
   Levar somente `bundle.age` e `envelope.json` dos IDs aprovados; recibos somente
   se explicitamente incluídos. Preservar originais, chaves e provas anteriores.
3. Conferir a identidade do destino/canal autenticado antes de enviar qualquer
   byte. A identidade privada age não acompanha o bundle no mesmo canal, conta
   ou conjunto. Conferir sua disponibilidade em custódia separada, sem imprimi-la
   em comandos, logs ou issue. O destinatário público sozinho não recupera dados.
4. No destino novo isolado, conferir bytes e SHA256 com a referência independente.
   Obter checkout confiável, dependências fixadas e imagem PostgreSQL compatível
   disponível por ID. As ferramentas atuais são host-only e usam diretórios
   privados fixos: preparar localização/permissões pelo runbook, sem adicionar
   upload web ou executar SQL manual para contornar guardas. Qualquer adaptação
   necessária deve ser revisada antes de efeitos. Não depender da fonte em claro
   ou da chave acessível apenas no host original para declarar perda do host testada.
5. Executar a verificação cifrada existente: autenticar todo o stream antes do
   restore, comparar inventários e confirmar cleanup do clone e staging antes do
   recibo. Chave errada, hash diferente, origem incerta, imagem incompatível ou
   cleanup inconclusivo impedem sucesso. Não reescrever envelope ou inventário.
6. Registrar privadamente IDs/hashes, origem, controles de acesso conferidos,
   tempos definidos, comparação e cleanup. Publicar apenas prova sanitizada e
   referência opaca; separar transferência verificada, restore de dados e eventual
   boot/ciclo/cutover, que têm procedimentos e autorizações distintos.

age autentica integridade do conteúdo cifrado, não a identidade do remetente.
Hash sem referência confiável não autentica origem: alguém com o destinatário
público pode substituir bundle e envelope por outro conteúdo cifrado válido.
Restaurar SQL exige origem confiável mesmo depois de decriptar com sucesso.

## Perda, indisponibilidade ou suspeita de comprometimento

O responsável e seu substituto devem conseguir localizar, por referências
privadas, cópia, chave e registro de hashes sem usar o computador perdido.
Recuperar acesso por procedimento previamente escolhido e obter a chave por
canal separado. Sem chave ou referência confiável, registrar impedimento;
não gerar uma nova identidade esperando que ela abra cópias antigas.

Em suspeita de comprometimento da chave, preservar as provas e avaliar quais
cópias ficaram expostas. Rotação protege cópias futuras, não revoga acesso a
ciphertext já obtido com a chave antiga. Não apagar cópias/chaves históricas
para resolver o incidente. No restore, manter quarentena; sessões, aprovações,
jobs, reservas e efeitos externos históricos exigem reconciliação própria antes
de qualquer retomada. Não há replay automático ou autorização de cutover.

## Limite de aceite desta preparação

Para verificar o envio manual informado, baixar a cópia da nuvem para uma pasta
nova, preservando o original; comparar seu hash com a referência local confiável
antes do restore. Um clone descartável local pode verificar os dados devolvidos
pela nuvem, mas não demonstra recuperação em outro computador ou independência
da chave se ela ainda for obtida somente no host original. Registrar cada limite.

Revisão do runbook e testes locais de age com fixture sintética demonstram
somente os contratos locais exercitados. A #117 permanece aberta até decisão
explícita completa; a #118 permanece bloqueada até essa decisão, infraestrutura
e autorização. O pai #28 permanece aberto até as provas e o aceite conjunto.
Ver [checkpoint e resultados desta sessão](../development/external-custody-checkpoint.md).
