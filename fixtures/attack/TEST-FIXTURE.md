# Fixture STIX reduzida para testes

`synthetic-enterprise-test.json` é uma coleção **sintética e reduzida**, não uma
release oficial. Usa cinco objetos attack-pattern reais e relações/táticas do
bundle Enterprise20.0 para testar o perfil de normalização e casos malformados.
O manifesto de coleção foi reduzido e o hash é diferente do bundle oficial.
Nunca usar esse arquivo como atualização do catálogo em uma implantação.

Os testes de transporte simulam HTTPS e commit, sem afirmar autenticidade desse
commit fictício. Os ensaios oficiais usam separadamente download completo fixado
por commit no repositório MITRE e a licença revisada em LICENSE.txt.

Fonte dos objetos originais: mitre-attack/attack-stix-data, commit
c2494b29dd268c46a5d0ea0990553e4327cd2253, Enterprise20.0.
Licença MITRE preservada neste diretório.
