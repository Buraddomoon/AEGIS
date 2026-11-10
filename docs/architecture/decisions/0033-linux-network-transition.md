# ADR0033 — Transição da faixa fixa do Linux Lab

Data:2026-11-10. Estado: implementação autorizada, ensaio nativo não autorizado.

O usuário pediu concluir os relatórios e retomar o laboratório real. A rede de
terceiros `qasrc` deve permanecer intacta. Seu pool172.30.0.0/16 sobrepõe a faixa
Linux antiga172.30.88.0/29. Consulta somente leitura em10/11 encontrou também
colisão para172.31.88.0/29; a candidata192.168.253.0/29 não colidiu com redes
Docker/rotas IPv4 observadas. Isso é uma observação temporal, não uma reserva.

O novo perfil Linux mantém uma única faixa revisada fixa192.168.253.0/29,
gateway.1, runner.2, cliente de identidade.3, API.4 e worker.5. Não aceitar subnets,
URLs ou comandos livres. Wazuh172.30.89.0/29 e o diagnóstico histórico permanecem
inalterados. Antes de qualquer create, repetir o preflight completo de sobreposição;
se outra rede/rota passar a ocupar a faixa, abortar sem modificar terceiros.

Centralizar endereços Linux no pacote do runner. Novas configurações/certificados
usam a nova faixa. Inventário de PKI deve continuar aceitando a origem Linux antiga
para revisão histórica, sem tornar um candidato antigo operacional. A transição
offline exige flag explícita, aceita somente antiga→nova e registra formato novo
com ambos os inventários/hash. Preservar três UUIDs, paths internos e todos os
arquivos originais; gerar quatro chaves distintas sem reutilizar as antigas.
Renovação comum conserva endpoint. Não aplicar arquivos ou binding implicitamente.

Implementação de PKI: `scripts/runner_pki.py prepare --migrate-linux-network`
gera somente um candidato offline no formato `/2`; sem essa flag, `prepare`
renova as chaves e conserva o endpoint existente. A opção recusa fontes novas,
Wazuh e qualquer outro perfil. `verify` valida ambos os formatos sem ativar
material. O default de `scripts/init_linux_lab.py` usa o runner Linux novo;
endereços históricos precisam ser solicitados explicitamente.

Novo plano/perfil e protocolo do probe de identidade têm versão própria para
evitar interpretar pedidos anteriores sob outro IP. Planos antigos não permitem
efeitos atuais; sua leitura histórica para cleanup continua possível com política
antiga exata e integridade conferida, nunca convertida por rehash.

Validar SAN/hostname/mTLS em loopback, deriva dos IDs, preservação da origem,
recusa de transição arbitrária/reversa/Wazuh, Compose renderizado sem startup,
coerência IPAM/receitas, colisão/rotas e leitores históricos antes de preparar
material real. Nenhuma mudança de banco, grants, volume, diário ou schema dos
labs antigos. Imagens antigas devem permanecer disponíveis; a nova imagem da
aplicação Demo b7 não é compatível com o banco a0 dos labs por mera troca de tag.

Um futuro ensaio identity-only continua sem marcador, banco, Wazuh ou ativação.
Pacote concreto/plano/imagem/CI e autorização humana específica precedem efeitos.
Esta decisão não autoriza iniciar recursos, renovar silenciosamente planos,
apagar fences, alterar rede/sysctl do host ou declarar retomada operacional.

Fontes oficiais consultadas:
[Docker bridge](https://docs.docker.com/engine/network/drivers/bridge/),
[firewalls Docker](https://docs.docker.com/engine/network/packet-filtering-firewalls/),
[verificação de hostname TLS](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname).
