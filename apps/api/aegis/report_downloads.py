"""Shared HTTP delivery policy for PDF exports; report construction remains separate."""

from fastapi import HTTPException, Response

from aegis.domain.validation import digest
from aegis.pdf_reporting import PDFBusyError, PDFExportError, PDFReportExporter
from aegis.security import rate_limit


def pdf_download(report: dict, filename: str, user_id: str) -> Response:
    rate_limit("pdf-report:" + user_id, 10, 60)
    try:
        content = PDFReportExporter().export(report)
    except PDFBusyError:
        raise HTTPException(
            503,
            "Outra exportação PDF está em andamento; tente novamente.",
            headers={"Retry-After": "2"},
        ) from None
    except PDFExportError as error:
        if str(error) == "pdf_report_integrity_mismatch":
            raise HTTPException(409, "Integridade do relatório não confirmada.") from None
        raise HTTPException(
            413, "Relatório excede os limites de PDF. Reduza o recorte ou exporte JSON/HTML."
        ) from None
    return Response(
        content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-AEGIS-Report-SHA256": digest(report),
        },
    )
