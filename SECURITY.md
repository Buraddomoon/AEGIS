# Política de segurança

O MVP 0.1 é uma demonstração local; não há promessa de maturidade empresarial ou suporte SLA. Reporte vulnerabilidades de modo privado ao proprietário do repositório, pelo canal privado já utilizado para colaboração. Se GitHub Private Vulnerability Reporting estiver habilitado, utilize-o. Não abra issue pública com detalhes exploráveis e não anexe segredos, dados pessoais ou corporativos.

Inclua versão/hash, componente, pré-requisitos, reprodução mínima no Demo Lab, impacto observado e sugestão de correção. Nenhum teste deve atingir infraestrutura de terceiros. Não executar validação ofensiva real sob pretexto de pesquisa sem autorização específica.

Controles, riscos residuais e aviso transitivo DiskCache estão em docs/security. `make audit` falha para ocorrências novas/não revisadas e mantém achados revisados visíveis. Uma exclusão ou classificação exige justificativa concreta e teste da premissa; não desabilitar verificações globalmente.

Divulgação e prazo de correção serão combinados conforme impacto; não inventamos endereço de contato ou processo externo inexistente.
