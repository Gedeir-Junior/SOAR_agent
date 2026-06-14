"""
reports/gerar_relatorio_pdf.py

Gerador de Relatório PDF

Recebe um RelatorioAmeacas e produz um PDF profissional com:
  - Capa com severidade geral e timestamp
  - Resumo executivo
  - Tabela de ameaças detectadas (ordenada por risco)
  - Seção detalhada por técnica MITRE: análise, evidências, recomendações
  - Rodapé com referência MITRE ATT&CK

Uso standalone:
    python reports/gerar_relatorio_pdf.py relatorio.json --saida report.pdf
"""
from __future__ import annotations

import sys
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline.agent_comparador_ameacas import AmeacaDetectada, RelatorioAmeacas

# ---------------------------------------------------------------------------
# Paleta de cores
# ---------------------------------------------------------------------------
COR_FUNDO_CAPA    = colors.HexColor("#0D1117")
COR_TITULO_CAPA   = colors.HexColor("#E6EDF3")
COR_SUBTITULO     = colors.HexColor("#8B949E")
COR_ACCENT        = colors.HexColor("#1F6FEB")
COR_HEADER_TABELA = colors.HexColor("#161B22")
COR_LINHA_PAR     = colors.HexColor("#F6F8FA")

SEV_CORES = {
    "critical": colors.HexColor("#DA3633"),
    "high":     colors.HexColor("#D29922"),
    "medium":   colors.HexColor("#1F6FEB"),
    "low":      colors.HexColor("#3FB950"),
    "info":     colors.HexColor("#8B949E"),
}

SEV_LABELS = {
    "critical": "CRÍTICO",
    "high":     "ALTO",
    "medium":   "MÉDIO",
    "low":      "BAIXO",
    "info":     "INFO",
}


# ---------------------------------------------------------------------------
# Estilos
# ---------------------------------------------------------------------------
def _criar_estilos() -> dict:
    base = getSampleStyleSheet()
    estilos = {}

    estilos["titulo_capa"] = ParagraphStyle(
        "titulo_capa",
        fontName="Helvetica-Bold",
        fontSize=26,
        textColor=COR_TITULO_CAPA,
        alignment=TA_CENTER,
        spaceAfter=8,
    )
    estilos["subtitulo_capa"] = ParagraphStyle(
        "subtitulo_capa",
        fontName="Helvetica",
        fontSize=13,
        textColor=COR_SUBTITULO,
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    estilos["secao"] = ParagraphStyle(
        "secao",
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=COR_ACCENT,
        spaceBefore=18,
        spaceAfter=8,
    )
    estilos["subsecao"] = ParagraphStyle(
        "subsecao",
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.HexColor("#24292F"),
        spaceBefore=10,
        spaceAfter=4,
    )
    estilos["corpo"] = ParagraphStyle(
        "corpo",
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#24292F"),
        alignment=TA_JUSTIFY,
        leading=15,
        spaceAfter=6,
    )
    estilos["codigo"] = ParagraphStyle(
        "codigo",
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#1F2328"),
        backColor=colors.HexColor("#F6F8FA"),
        leftIndent=8,
        rightIndent=8,
        spaceBefore=2,
        spaceAfter=2,
        leading=12,
        borderPad=4,
    )
    estilos["bullet"] = ParagraphStyle(
        "bullet",
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#24292F"),
        leftIndent=16,
        bulletIndent=4,
        leading=14,
        spaceAfter=3,
    )
    estilos["rodape"] = ParagraphStyle(
        "rodape",
        fontName="Helvetica",
        fontSize=8,
        textColor=COR_SUBTITULO,
        alignment=TA_CENTER,
    )
    return estilos


# ---------------------------------------------------------------------------
# Helpers de formatação
# ---------------------------------------------------------------------------
def _badge_severidade(severidade: str) -> str:
    """Retorna texto colorido HTML para o Paragraph do ReportLab."""
    cor = SEV_CORES.get(severidade.lower(), SEV_CORES["info"])
    label = SEV_LABELS.get(severidade.lower(), severidade.upper())
    hex_cor = cor.hexval() if hasattr(cor, "hexval") else "#8B949E"
    return f'<font color="{hex_cor}"><b>{label}</b></font>'


def _escapar(texto: str) -> str:
    """Escapa caracteres especiais do XML/HTML para uso em Paragraph."""
    return (
        texto
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ---------------------------------------------------------------------------
# Seções do PDF
# ---------------------------------------------------------------------------
def _secao_capa(relatorio: RelatorioAmeacas, estilos: dict) -> list:
    elementos = []

    elementos.append(Spacer(1, 3 * cm))

    elementos.append(Paragraph("RELATÓRIO DE ANÁLISE DE AMEAÇAS", estilos["titulo_capa"]))
    elementos.append(Spacer(1, 0.3 * cm))
    elementos.append(Paragraph("MITRE ATT&amp;CK Threat Detection Report", estilos["subtitulo_capa"]))
    elementos.append(Spacer(1, 1.5 * cm))

    sev = relatorio.severidade_geral.lower()
    cor_sev = SEV_CORES.get(sev, SEV_CORES["medium"])
    label_sev = SEV_LABELS.get(sev, sev.upper())

    info_data = [
        ["Arquivo analisado", _escapar(relatorio.arquivo_log)],
        ["Linhas analisadas", str(relatorio.total_linhas_analisadas)],
        ["Ameaças detectadas", str(relatorio.total_ameacas_detectadas)],
        ["Severidade geral", label_sev],
        ["Gerado em", relatorio.timestamp_geracao],
    ]

    tabela_info = Table(info_data, colWidths=[5 * cm, 11 * cm])
    tabela_info.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 11),
        ("TEXTCOLOR",  (0, 0), (0, -1), COR_SUBTITULO),
        ("TEXTCOLOR",  (1, 0), (1, -1), COR_TITULO_CAPA),
        ("BACKGROUND", (0, 0), (-1, -1), COR_FUNDO_CAPA),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COR_FUNDO_CAPA, colors.HexColor("#161B22")]),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TEXTCOLOR",  (1, 3), (1, 3), cor_sev),
        ("FONTNAME",   (1, 3), (1, 3), "Helvetica-Bold"),
    ]))
    elementos.append(tabela_info)
    elementos.append(PageBreak())
    return elementos


def _secao_resumo_executivo(relatorio: RelatorioAmeacas, estilos: dict) -> list:
    elementos = []
    elementos.append(Paragraph("Resumo Executivo", estilos["secao"]))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=COR_ACCENT))
    elementos.append(Spacer(1, 0.3 * cm))

    if relatorio.resumo_executivo:
        elementos.append(Paragraph(_escapar(relatorio.resumo_executivo), estilos["corpo"]))
    else:
        elementos.append(Paragraph(
            f"Foram detectadas {relatorio.total_ameacas_detectadas} técnica(s) MITRE ATT&amp;CK "
            f"no arquivo de log analisado.",
            estilos["corpo"],
        ))

    elementos.append(Spacer(1, 0.5 * cm))
    return elementos


def _secao_tabela_resumo(relatorio: RelatorioAmeacas, estilos: dict) -> list:
    elementos = []
    elementos.append(Paragraph("Resumo das Ameaças Detectadas", estilos["secao"]))
    elementos.append(HRFlowable(width="100%", thickness=0.5, color=COR_ACCENT))
    elementos.append(Spacer(1, 0.3 * cm))

    cabecalho = [
        Paragraph("<b>Técnica</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
        Paragraph("<b>Nome</b>",    ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
        Paragraph("<b>Tática</b>",  ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
        Paragraph("<b>Sev.</b>",    ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
        Paragraph("<b>Evid.</b>",   ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
        Paragraph("<b>Risco</b>",   ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
    ]

    linhas = [cabecalho]
    for a in relatorio.ameacas:
        cor_sev = SEV_CORES.get(a.severidade.lower(), SEV_CORES["info"])
        label_sev = SEV_LABELS.get(a.severidade.lower(), a.severidade.upper())
        st_sev = ParagraphStyle("sev", fontName="Helvetica-Bold", fontSize=9, textColor=cor_sev)
        st_normal = ParagraphStyle("td", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#24292F"))

        linhas.append([
            Paragraph(_escapar(a.tecnica_id), st_normal),
            Paragraph(_escapar(a.nome_tecnica[:45] + ("…" if len(a.nome_tecnica) > 45 else "")), st_normal),
            Paragraph(_escapar(a.tatica), st_normal),
            Paragraph(label_sev, st_sev),
            Paragraph(str(a.contagem_evidencias), st_normal),
            Paragraph(f"{a.score_risco:.3f}", st_normal),
        ])

    tabela = Table(linhas, colWidths=[2.2*cm, 6.5*cm, 3.5*cm, 1.8*cm, 1.5*cm, 1.8*cm])
    tabela.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), COR_HEADER_TABELA),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COR_LINHA_PAR]),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D7DE")),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elementos.append(tabela)
    elementos.append(Spacer(1, 0.5 * cm))
    return elementos


def _secao_detalhes_ameaca(ameaca: AmeacaDetectada, indice: int, estilos: dict) -> list:
    elementos = []

    sev_label = SEV_LABELS.get(ameaca.severidade.lower(), ameaca.severidade.upper())
    cor_sev   = SEV_CORES.get(ameaca.severidade.lower(), SEV_CORES["medium"])
    hex_sev   = "#{:02X}{:02X}{:02X}".format(
        int(cor_sev.red * 255), int(cor_sev.green * 255), int(cor_sev.blue * 255)
    )

    titulo = (
        f'{indice}. <font color="{hex_sev}">[{sev_label}]</font> '
        f'{_escapar(ameaca.tecnica_id)} — {_escapar(ameaca.nome_tecnica)}'
    )
    elementos.append(Paragraph(titulo, estilos["secao"]))
    elementos.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#D0D7DE")))
    elementos.append(Spacer(1, 0.2 * cm))

    # Metadados
    meta = [
        ["Tática",       f"{ameaca.tatica} ({ameaca.tatica_id})"],
        ["Plataformas",  ", ".join(ameaca.plataformas_mitre) or "N/A"],
        ["Evidências",   f"{ameaca.contagem_evidencias} linha(s) de log"],
        ["Confiança",    f"{ameaca.confianca_media:.3f}"],
        ["Score de risco", f"{ameaca.score_risco:.3f}"],
        ["Referência",   ameaca.url_mitre],
    ]
    st_label = ParagraphStyle("ml", fontName="Helvetica-Bold", fontSize=9, textColor=COR_SUBTITULO)
    st_valor = ParagraphStyle("mv", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#24292F"))
    meta_rows = [[Paragraph(_escapar(k), st_label), Paragraph(_escapar(v), st_valor)] for k, v in meta]
    t_meta = Table(meta_rows, colWidths=[3.5*cm, 13.8*cm])
    t_meta.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    elementos.append(t_meta)
    elementos.append(Spacer(1, 0.3 * cm))

    # Descrição MITRE
    elementos.append(Paragraph("Descrição MITRE ATT&amp;CK", estilos["subsecao"]))
    elementos.append(Paragraph(_escapar(ameaca.descricao_mitre[:600]), estilos["corpo"]))

    # Como aparece em logs
    elementos.append(Paragraph("Manifestação em Logs", estilos["subsecao"]))
    elementos.append(Paragraph(_escapar(ameaca.descricao_semantica_log[:600]), estilos["corpo"]))

    # Análise LLM
    if ameaca.analise_llm:
        elementos.append(Paragraph("Análise Técnica", estilos["subsecao"]))
        elementos.append(Paragraph(_escapar(ameaca.analise_llm), estilos["corpo"]))

    # Evidências
    elementos.append(Paragraph(f"Evidências ({ameaca.contagem_evidencias})", estilos["subsecao"]))
    for ev in ameaca.evidencias[:8]:  # máximo 8 por página
        linha_fmt = f"<b>L{ev.numero_linha}</b> [score={ev.score_similaridade:.3f}]  {_escapar(ev.linha_original[:120])}"
        elementos.append(Paragraph(linha_fmt, estilos["codigo"]))
        if ev.descricao_comportamental:
            elementos.append(Paragraph(
                f"  ↳ {_escapar(ev.descricao_comportamental[:150])}",
                estilos["bullet"],
            ))

    if len(ameaca.evidencias) > 8:
        elementos.append(Paragraph(
            f"… e mais {len(ameaca.evidencias) - 8} evidência(s) omitidas.",
            estilos["bullet"],
        ))

    # Recomendações
    if ameaca.recomendacoes:
        elementos.append(Paragraph("Recomendações", estilos["subsecao"]))
        for i, rec in enumerate(ameaca.recomendacoes, 1):
            elementos.append(Paragraph(f"{i}. {_escapar(rec)}", estilos["bullet"]))

    elementos.append(Spacer(1, 0.5 * cm))
    return elementos


# ---------------------------------------------------------------------------
# Numeração de páginas
# ---------------------------------------------------------------------------
def _rodape_paginas(canvas, doc):
    canvas.saveState()
    estilo_rodape = ParagraphStyle(
        "rodape_fn",
        fontName="Helvetica",
        fontSize=8,
        textColor=COR_SUBTITULO,
    )
    w, h = A4
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(COR_SUBTITULO)
    canvas.drawCentredString(w / 2, 1.2 * cm, f"Página {doc.page}")
    canvas.drawString(2 * cm, 1.2 * cm, "MITRE ATT&CK Threat Detection Report")
    canvas.drawRightString(w - 2 * cm, 1.2 * cm, "Confidencial")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Função principal
# ---------------------------------------------------------------------------
def gerar_pdf(relatorio: RelatorioAmeacas, caminho_saida: Path) -> Path:
    """
    Gera o relatório PDF a partir de um RelatorioAmeacas.

    Args:
        relatorio: estrutura de dados com todas as ameaças detectadas.
        caminho_saida: caminho do arquivo PDF a ser gerado.

    Returns:
        caminho_saida confirmado após a geração.
    """
    caminho_saida.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(caminho_saida),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.5 * cm,
        title="Relatório de Análise de Ameaças",
        author="Threat Detection Agent",
        subject="MITRE ATT&CK Log Analysis",
    )

    estilos = _criar_estilos()
    historia: list = []

    # 1. Capa
    historia.extend(_secao_capa(relatorio, estilos))

    # 2. Resumo executivo
    historia.extend(_secao_resumo_executivo(relatorio, estilos))

    # 3. Tabela de resumo
    if relatorio.ameacas:
        historia.extend(_secao_tabela_resumo(relatorio, estilos))
        historia.append(PageBreak())

    # 4. Detalhes por ameaça
    if relatorio.ameacas:
        historia.append(Paragraph("Análise Detalhada por Técnica", estilos["secao"]))
        historia.append(HRFlowable(width="100%", thickness=0.5, color=COR_ACCENT))
        historia.append(Spacer(1, 0.5 * cm))

        for i, ameaca in enumerate(relatorio.ameacas, 1):
            historia.extend(_secao_detalhes_ameaca(ameaca, i, estilos))
            if i < len(relatorio.ameacas):
                historia.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#D0D7DE")))
    else:
        historia.append(Paragraph(
            "Nenhuma ameaça foi detectada no arquivo de log analisado.",
            estilos["corpo"],
        ))

    doc.build(historia, onFirstPage=_rodape_paginas, onLaterPages=_rodape_paginas)

    print(f"[+] PDF gerado: {caminho_saida}")
    return caminho_saida


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse, dataclasses

    parser = argparse.ArgumentParser(description="Gera relatório PDF a partir do JSON do comparador.")
    parser.add_argument("relatorio_json", type=Path, help="JSON de saída do agente comparador.")
    parser.add_argument("--saida", type=Path, default=Path("relatorio_ameacas.pdf"))
    args = parser.parse_args()

    dados = json.loads(args.relatorio_json.read_text(encoding="utf-8"))

    # Re-hidrata dataclasses a partir do JSON
    from agents.agente_comparador_ameacas import EvidenciaLog
    ameacas = []
    for a in dados.get("ameacas", []):
        evidencias = [EvidenciaLog(**e) for e in a.pop("evidencias", [])]
        ameacas.append(AmeacaDetectada(evidencias=evidencias, **a))

    dados.pop("ameacas")
    relatorio = RelatorioAmeacas(ameacas=ameacas, **dados)

    gerar_pdf(relatorio, args.saida)