# Checkpoint — entrega #16: conversão Sigma

18/11/2026, retomada após pedido explícito para resolver o bloqueio e entregar
#85/#86. Não foi necessária outra issue. O
[ADR0036](../architecture/decisions/0036-isolated-sigma-converter.md) substituiu
a espera por publicação prevista no ADR0035: conversor oficial compatível em
venv/processo separados, core1.5.1/OpenSearch2.0.3/Elasticsearch2.1.1 e18pins/hashes.
Parser2.0.1 e locks da aplicação preservados; sem backend incompatível na API,
patch de METADATA, código upstream copiado ou serviço de rede adicional.

#84 entregou o isolamento e sua validação;#85 implementou perfil/pipeline/API
fechados;#86 implementou seleção de versão, query/procedência e download validado.
Fonte executável `69ae1e4f2730c64b93841d1f8a67c3e2250ada16`. Ver
[provas completas](../evidence/sigma-conversion-2026-11-18/README.md) e
[operação/limites](../integrations/sigma.md). A
[pesquisa inicial negativa](../evidence/sigma-compatibility-2026-11-18/README.md)
é preservada como histórico correto dos pacotes publicados.

Validação local:139Python pertinentes/115React/21segurança glob; lint/tipos/build
e auditorias aprovados (Python1finding DiskCache revisado e import proibido;
npm0). Firefox real:5runs/20testes Demo/2snapshots/4PDFs/17capturas/0errosJS,
mais query offline/download real com hashes conferidos e relatórios preservados.
Imagem dedicada final construída/testada sem rede, escrita ou volumes; Demo ativo
permanece na imagem b8 anterior. Falhas intermediárias e diferença entre
implementado/testado/implantado constam das provas.

CI integral da fonte69ae1e4:
[44379443285 SUCCESS](https://github.com/Buraddomoon/AEGIS/actions/runs/44379443285),
3781Python/9skips existentes e115React. Quatro jobs Python e React conferidos.
Aceite conjunto#16 atendido com#84/#85/#86; entrega encerrada. Último commit
somente documental não altera os inputs executáveis validados.

Conversão não consulta SIEM, não valida índice físico, não implanta regra nem
comprova eficácia. Candidato/hash antigos, scopes, aprovações, evidências e
histórico preservados. Sem Linux/Wazuh, marcador, volume original, PKI ou qasrc.
Validação nativa da query pertence à#17, fora desta sessão e sem autorização
implícita. Commits/sincronização registrados nas issues. Parar sem outra entrega.
