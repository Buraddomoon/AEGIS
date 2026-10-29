
### Campo opcional ExposedPorts em imagem limpa

Inspeção real somente de metadados da imagem nova em2026-10-29 encontrou falha de
template quando ExposedPorts está ausente. Projeções de imagem/container agora
usam index .Config "ExposedPorts"; ausência normaliza para null e o guard continua
recusando portas declaradas. Não aceitar uma porta real para contornar o template.
Teste nativo opcional AEGIS_TEST_RUNNER_IMAGE_ID exige ID explícito e só consulta
imageinspect. Usa intent/DBid sintéticos em temporários apenas para compilar receita;
não registra ownership real nem cria/inicia/inspeciona o DB fictício. Não comprova
Lab/SQL/proveniência. Rodada runtime+lifecycle95passou incluindo essa consulta real.
