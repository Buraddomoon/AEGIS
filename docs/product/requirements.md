# Escopo da versão funcional 0.1

Pergunta central: há evidência suficiente de que um comportamento executado foi observado e detectado? O MVP responde dentro de um laboratório sintético explicitamente identificado, sem extrapolação para segurança empresarial.

Fluxo obrigatório implementado: autenticar → consultar catálogo → criar campanha no Demo Lab → solicitar execução → revisar/aprovar escopo → confirmar início → worker → eventos → correlação → cleanup → evidências → indicadores → relatório → repetição/comparação.

Escopo técnico: monólito modular com interfaces de adapter, persistência relacional e migrations, fila durável, sessões/RBAC, auditoria, API REST versionada, SPA pt-BR. Catálogo ATT&CK oficial completo do snapshot e quatro simulações Demo. Wazuh somente leitura com testes de contrato; Sigma parsing/versionamento, sem implantação.

Critérios semânticos: DETECTED exige execução confirmada e alerta da regra esperada com identidade, marcador, comportamento e tempo compatíveis. OBSERVED_NOT_ALERTED exige observação correlacionada e consulta completa de alertas. NO_TELEMETRY significa insuficiência de evidência de coleta, não falha de detecção confirmada. INCONCLUSIVE cobre coleta incompleta/indisponível. EXECUTION_FAILED não entra no denominador válido. NOT_TESTED permanece distinto de catálogo.

Fora do release: execução real remota, agendamento de laboratório real, Caldera, Windows real, PDF, recomendações LLM, multi-tenancy e SSO. Não anunciar funcionalidades futuras como operacionais.

Agendamento de campanhas Demo foi entregue como extensão do MVP, sob aprovação explícita e limites persistentes. Consulte [operação](../operations/scheduling.md) e ADR 0002 para políticas, contratos e validação.
