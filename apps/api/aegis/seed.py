import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.config import settings
from aegis.models import Asset, AttackTechnique, Laboratory, TestDefinition, uid

DEMO_TESTS = [
    {"id": "demo-shell", "name": "Interpretador Unix • marcador benigno",
     "description": "Simula a telemetria de um shell que escreve um marcador. Nenhum processo é executado no host.",
     "technique_id": "T1059.004", "behavior": "unix-shell-marker", "demo_outcome": "DETECTED"},
    {"id": "demo-powershell", "name": "PowerShell • script benigno",
     "description": "Representação sintética de execução PowerShell benigna. Não representa validação de um endpoint Windows.",
     "technique_id": "T1059.001", "behavior": "powershell-marker", "demo_outcome": "OBSERVED_NOT_ALERTED"},
    {"id": "demo-process-discovery", "name": "Descoberta de processos • coleta ausente",
     "description": "Simula enumeração de processos sem evidência de coleta para demonstrar incerteza de telemetria.",
     "technique_id": "T1057", "behavior": "process-enumeration", "demo_outcome": "NO_TELEMETRY"},
    {"id": "demo-file-marker", "name": "Arquivo temporário • correlação de logs",
     "description": "Artefato sintético para testar o fluxo de coleta indisponível. Sem associação ATT&CK: criação de arquivo genérico não justifica uma técnica.",
     "technique_id": None, "behavior": "temporary-marker", "demo_outcome": "INCONCLUSIVE"},
]


def seed(db: Session) -> dict:
    document = json.loads((settings().fixtures_path / "attack/enterprise.json").read_text())
    existing = set(db.scalars(select(AttackTechnique.id)))
    for item in document["techniques"]:
        if item["id"] not in existing:
            db.add(AttackTechnique(**item))
    db.flush()
    lab = db.scalar(select(Laboratory).where(Laboratory.kind == "demo"))
    if not lab:
        lab = Laboratory(id=uid(), name="Demo Lab", kind="demo", authorized=True,
                         owner="Administrador local", environment_version=1,
                         description="Ambiente fictício. Nenhuma máquina externa é acessada.",
                         isolation="Adaptadores em memória; sem subprocessos, rede ou acesso ao host.")
        db.add(lab)
        db.flush()
        db.add(Asset(laboratory_id=lab.id, name="endpoint-demo-01", platform="Synthetic",
                     external_id="aegis-demo-01", synthetic=True))
    for item in DEMO_TESTS:
        if not db.get(TestDefinition, item["id"]):
            db.add(TestDefinition(**item, expected_rule="aegis-" + item["id"],
                                  cleanup="Descartar contexto sintético; nenhum arquivo externo é criado.",
                                  prerequisites="Demo Lab autorizado e worker ativo.", approved=True))
    db.commit()
    return {"laboratory_id": lab.id, "dataset_version": document["version"],
            "techniques": len(document["techniques"]), "tests": len(DEMO_TESTS)}
