# Revisão de segurança — backups cifrados, 2026-10-26

Escopo: ADR0016, vault.py, extensões de demo_backup.py e testes vault/CLI.
Revisão especializada somente leitura pelo agente architecture_review, reutilizado;
sem acesso a .local/.env, Docker, rede ou execução de ensaios pelo revisor.
Inspeção final do código59c02f9 não identificou outro bloqueador concreto.
Isso não substitui auditoria independente ou prova formal da implementação age.

## Achados corrigidos

1. Médio, vínculo de ciphertext: SHA calculado antes de decrypt no mesmo FD
   não impedia alteração in-place por outro processo. X25519 não autentica
   remetente; um ciphertext válido diferente poderia ser associado ao hash
   anterior. CipherReader agora calcula SHA256/count de todos os bytes entregues
   ao decrypter e confere antes de unpack/yield. Regressão faz exatamente a troca
   após pré-checagem, exige VaultError e staging removido. Confirmado por inspeção.
2. Baixo, plano advisory: data de cópia recente não verificada do mesmo snapshot
   podia influenciar sua ordem de retenção. verified_records agora seleciona
   datas apenas entre cópias verificadas e com chave local. Regressão com mais de
   sete snapshots bons prova ações idênticas após re-selagem não verificada do
   mais antigo. Confirmado por inspeção. Nunca existiu exclusão automática.

Testes adicionais exigem stream autenticado completo, recusa de corrupção/final/
truncamento/extra, chave/hash errados, limites e arquivos especiais/links/ownership.
Inventário read-only não modifica bytes/mtime, não considera duplicatas como
snapshots distintos e preserva cópias sem verificação ou chave disponível.
Subprocesso com audit hook recusa import opcional na API/worker; não carrega pyrage.
CLI mantém restore network=none sem destino/SQL/container de escolha do usuário.
Sucesso só após cleanup de clone e staging; falhas não publicam recibo.

## Limites operacionais

- Quem possui destinatário público pode criar outro ciphertext válido. Origem e
  expected SHA precisam ser confiáveis; envelope/recibo locais são editáveis,
  não assinatura, atestação remota ou comprovação de custódia independente.
- Chave local0600 não é proteção contra root/mesmo usuário comprometido ou perda
  do disco. Sem hardware/KMS, senha adicional, escrow ou envio externo nesta etapa.
- Cópias originais em claro são preservadas. Scratch é privado e removido em
  saída normal; SIGKILL/filesystem podem deixar resíduos. Unlink não é secure erase;
  filesystem/swap criptografados dependem da instalação do operador.
- O pacote é de dados: não contém roles, segredos, configuração, imagens, Redis,
  PKI ou diários do runner. Schema/imagem compatíveis continuam obrigatórios.
- Dependência pyrage1.4.0 fixada por hash, extra host-only, fora da imagem runtime.
  Auditoria de advisories Python não equivale a auditoria de todo código Rust
  compilado. Licenças transitivas conservam avisos próprios.
- Sem cutover, RPO/RTO, exclusão, nova simulação Linux/Wazuh ou eficácia defensiva
  inferida desse recurso. Destino externo depende da decisão própria do usuário.

[Testes/recibo real](../evidence/encrypted-backups-2026-10-26/README.md).
