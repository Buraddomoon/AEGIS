# Ampliação Linux — #15

Escopo exclusivo: #81 → #82 → #83. Dependência #5 concluída; autorizações
históricas #5/#14 consumidas. Não iniciar outra entrega a partir deste arquivo.

[Especificação revisada](linux-behaviors-spec.md): dois perfis opt-in,
`linux-process-canary-v1` sem técnica e `linux-shell-canary-v1` limitado a
T1059.004. Perfis Linux/Atomic anteriores preservados; Demo continua sintético.

Implementação #82 usa programas fixos, identidade por hash de revisão/fonte,
binding de um único teste e aprovação segregada. Reutiliza supervisor, dispatch
durável, recibos, cleanup, validação e relatórios. Não há conector defensivo novo;
com coletor/regra ausente o resultado é INCONCLUSIVE. PID/exit/stdout e arquivo
são recibos do executor, nunca evidência de detecção.

Validação local:135casos API/worker/binding/domínio e212casos runner/protocolo/
transporte/Atomic/comportamentos aprovados, com sobreposição entre rodadas.
Lint e build aprovados. [Provas e limites](../evidence/linux-behaviors-2026-11-18/PREPARATION.md).
Dois asserts de inventário da primeira CI foram corrigidos em `9e614cb`;
24regressões locais de fluxo Demo/publicação ATT&CK aprovadas.
[CI integral44313563809](https://github.com/Buraddomoon/AEGIS/actions/runs/44313563809)
SUCCESS na fonte `9e614cb829cccaa70b21ff7a286418a5482fa771`:3703Python/9skips
opcionais e98React, quatro grupos e React conferidos. [Contagens e limites](../evidence/linux-behaviors-2026-11-18/CI.md).
Escopo técnico de #81/#82 atendido; #83 e aceite do pai ainda pendentes.
Nenhuma imagem nova implantada ou ensaio nativo
realizado nesta preparação. O banco Demo e os volumes originais não recebem seed
nem migração para disponibilizar esses testes; seed somente em schemas de teste.

#83 permanece bloqueada: falta autorização humana nova de pacote delimitado,
uma tentativa por novo teste, com imagem/código, revisões, lab/ativo/IDs, janela,
contas, fonte defensiva disponível ou ausente, preservação e recuperação/cleanup.
Sem essa aprovação, não iniciar serviços Linux/Wazuh, abrir volumes originais,
renovar binding real ou executar o efeito. O pedido da issue não concede operação.

Para preparar um pacote futuro, revisar a fonte e gerar imagens sob tags novas,
sem substituir tags retidas; conferir IDs e compatibilidade b7/33 antes de qualquer
início autorizado. Configurar um perfil por identidade/journal próprio, sem
reutilizar o binding/diário original de outro perfil ou pacotes consumidos.
Usar os controles do [runbook histórico](../../labs/linux/CAMPAIGN-ASSAY.md), adaptados
explicitamente aos dois perfis novos e ao estado b7 atual. Seus IDs, imagens,
pacotes e propostas de migração são históricos; não reutilizar nem executar o smoke
histórico do marcador.
Uma troca de perfil invalida hash/revisão/preflight/aprovações anteriores.

Cleanup falho ou RPC ambígua: manter reserva e histórico, consultar a mesma
identidade/spec/geração, cancelar se ativo e solicitar somente cleanup. Não repetir
start, apagar arquivos desconhecidos, journal/fences ou liberar por HTTP404.
Recuperação manual exige revisão do runner original; guardar a prova persistida de
CLEANED antes de liberar. #15 continua aberta até ensaio e aceite conjunto reais.
