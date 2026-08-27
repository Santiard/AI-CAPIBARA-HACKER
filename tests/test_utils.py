import unittest
import os
from src.utils.report_formatter import (
    AuditReportData,
    format_markdown_report,
    generate_sample_report_data
)
from src.utils.pdf_exporter import export_report_to_pdf

class TestReportUtils(unittest.TestCase):

    def setUp(self):
        self.sample_data = generate_sample_report_data()
        self.pdf_output_path = os.path.join("exports", "test_report_unit.pdf")

    def tearDown(self):
        # Limpiar archivo temporal si se creó
        if os.path.exists(self.pdf_output_path):
            try:
                os.remove(self.pdf_output_path)
            except OSError:
                pass

    def test_audit_report_data_model(self):
        """Verifica la validación del modelo AuditReportData."""
        report = AuditReportData(**self.sample_data)
        self.assertEqual(report.target_ip, "192.168.1.50")
        self.assertEqual(len(report.services_inventory), 5)
        self.assertEqual(len(report.vulnerabilities), 3)

    def test_format_markdown_report(self):
        """Verifica que el informe Markdown contenga todas las secciones requeridas."""
        md_text = format_markdown_report(self.sample_data)

        self.assertIn("# 🦫 INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD", md_text)
        self.assertIn("## 1. 📊 Resumen Ejecutivo", md_text)
        self.assertIn("## 2. 🔍 Inventario de Activos", md_text)
        self.assertIn("## 3. 🛡️ Vulnerabilidades Correlacionadas", md_text)
        self.assertIn("## 4. 🛠️ Plan de Remediación", md_text)
        self.assertIn("## 5. ⚖️ Dictamen de Validación", md_text)
        self.assertIn("CVE-2011-2523", md_text)

    def test_export_report_to_pdf(self):
        """Verifica la compilación del PDF y que el archivo generado sea válido."""
        generated_path = export_report_to_pdf(self.sample_data, self.pdf_output_path)

        self.assertTrue(os.path.exists(generated_path), "El PDF generado debe existir en disco.")
        file_size = os.path.getsize(generated_path)
        self.assertGreater(file_size, 1000, "El PDF generado debe tener contenido (> 1KB).")


if __name__ == "__main__":
    unittest.main()
