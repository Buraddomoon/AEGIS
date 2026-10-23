from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.catalog.store import initialize, reference
from aegis.config import settings
from aegis.models import Asset, AttackTechnique, Laboratory, TestDefinition, uid

DEMO_TESTS = [
    {
        "id": "demo-shell",
        "name": "Interpretador Unix • marcador benigno",
        "description": "Simula a telemetria de um shell que escreve um marcador. Nenhum processo é executado no host.",
        "technique_id": "T1059.004",
        "behavior": "unix-shell-marker",
        "demo_outcome": "DETECTED",
    },
    {
        "id": "demo-powershell",
        "name": "PowerShell • script benigno",
        "description": "Representação sintética de execução PowerShell benigna. Não representa validação de um endpoint Windows.",
        "technique_id": "T1059.001",
        "behavior": "powershell-marker",
        "demo_outcome": "OBSERVED_NOT_ALERTED",
    },
    {
        "id": "demo-process-discovery",
        "name": "Descoberta de processos • coleta ausente",
        "description": "Simula enumeração de processos sem evidência de coleta para demonstrar incerteza de telemetria.",
        "technique_id": "T1057",
        "behavior": "process-enumeration",
        "demo_outcome": "NO_TELEMETRY",
    },
    {
        "id": "demo-file-marker",
        "name": "Arquivo temporário • correlação de logs",
        "description": "Artefato sintético para testar o fluxo de coleta indisponível. Sem associação ATT&CK: criação de arquivo genérico não justifica uma técnica.",
        "technique_id": None,
        "behavior": "temporary-marker",
        "demo_outcome": "INCONCLUSIVE",
    },
]


def seed(db: Session) -> dict:
    directory = settings().fixtures_path / "attack"
    initialize(
        db, (directory / "enterprise.json").read_bytes(), (directory / "LICENSE.txt").read_bytes()
    )
    catalog = reference(db)
    lab = db.scalar(select(Laboratory).where(Laboratory.kind == "demo"))
    if not lab:
        lab = Laboratory(
            id=uid(),
            name="Demo Lab",
            kind="demo",
            authorized=True,
            owner="Administrador local",
            environment_version=1,
            description="Ambiente fictício. Nenhuma máquina externa é acessada.",
            isolation="Adaptadores em memória; sem subprocessos, rede ou acesso ao host.",
        )
        db.add(lab)
        db.flush()
        db.add(
            Asset(
                laboratory_id=lab.id,
                name="endpoint-demo-01",
                platform="Synthetic",
                external_id="aegis-demo-01",
                synthetic=True,
            )
        )
    for item in DEMO_TESTS:
        if not db.get(TestDefinition, item["id"]):
            db.add(
                TestDefinition(
                    **item,
                    expected_rule="aegis-" + item["id"],
                    cleanup="Descartar contexto sintético; nenhum arquivo externo é criado.",
                    prerequisites="Demo Lab autorizado e worker ativo.",
                    approved=True,
                )
            )
    if not db.get(TestDefinition, "linux-file-marker-v1"):
        db.add(
            TestDefinition(
                id="linux-file-marker-v1",
                name="Linux • marcador benigno real",
                description="Cria e remove 43 bytes no tmpfs do runner isolado. Comprovante não é telemetria defensiva.",
                technique_id=None,
                behavior="temporary-marker",
                execution_kind="linux_marker",
                platform="Linux",
                cleanup="Remover somente proof.marker e receipt.json do diretório UUID; confirmação pelo runner.",
                prerequisites="Binding revisado, preflight mTLS vigente, laboratório autorizado e aprovação separada.",
                risk="low",
                approved=True,
                expected_rule="",
                demo_outcome="",
            )
        )
    active_count = db.scalar(
        select(func.count())
        .select_from(AttackTechnique)
        .where(
            AttackTechnique.present_in_current,
            ~AttackTechnique.revoked,
            ~AttackTechnique.deprecated,
        )
    )
    db.commit()
    return {
        "laboratory_id": lab.id,
        "dataset_version": catalog["version"],
        "catalog_release_id": catalog["release_id"],
        "techniques": active_count,
        "tests": len(DEMO_TESTS),
    }
