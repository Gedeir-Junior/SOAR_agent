from fpdf import FPDF
from datetime import datetime
import os

class SOCReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_pdf(self, scan_results, filename):
        pdf = FPDF()
        pdf.add_page()
        
        # Cabeçalho
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Relatório de Análise de Segurança (Log Agent)", ln=True, align='C')
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(10)

        # Resumo
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"Arquivo Analisado: {filename}", ln=True)
        pdf.cell(0, 10, f"Total de Ameaças Detectadas: {len(scan_results)}", ln=True)
        pdf.ln(5)

        # Detalhes das Ameaças
        for idx, threat in enumerate(scan_results):
            pdf.set_fill_color(230, 230, 230)
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 10, f"Incidente #{idx+1}: {threat['mitre_name']}", ln=True, fill=True)
            
            pdf.set_font("Arial", "I", 10)
            pdf.multi_cell(0, 8, f"Log Original: {threat['raw_log']}")
            
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 8, f"Técnica MITRE: {threat['mitre_id']}", ln=True)
            
            pdf.set_text_color(0, 100, 0)
            pdf.multi_cell(0, 8, f"Sugestão de Remediação: {threat['suggestion']}")
            
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)

        report_path = os.path.join(self.output_dir, f"report_{int(datetime.now().timestamp())}.pdf")
        pdf.output(report_path)
        return report_path