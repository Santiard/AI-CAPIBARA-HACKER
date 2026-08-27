import unittest
import json
import os
from src.tools.nmap_parser import (
    parse_nmap_xml,
    generate_mock_scan,
    parse_nmap_scan_tool,
    ScanTargetReport
)
from src.tools.cvss_calculator import (
    evaluate_vulnerability,
    get_severity_label,
    get_impact_recommendation,
    cvss_evaluator_tool
)

class TestNmapParser(unittest.TestCase):

    def setUp(self):
        self.sample_xml_path = os.path.join("data", "scans", "sample_scan.xml")

    def test_parse_sample_scan_xml(self):
        """Verifica que el parser de XML extraiga correctamente hosts, puertos y CPEs."""
        self.assertTrue(os.path.exists(self.sample_xml_path), "El archivo sample_scan.xml debe existir.")
        report = parse_nmap_xml(self.sample_xml_path)

        self.assertIsInstance(report, ScanTargetReport)
        self.assertEqual(report.target_ip, "192.168.1.50")
        self.assertEqual(report.hostname, "srv-corp-production.local")
        self.assertGreater(report.open_ports_count, 0)

        # Verificar servicios críticos detectados
        ports = [s.port for s in report.services]
        self.assertIn(21, ports)
        self.assertIn(22, ports)
        self.assertIn(80, ports)

        # Verificar extracción de CPE
        ftp_service = next(s for s in report.services if s.port == 21)
        self.assertEqual(ftp_service.product, "vsftpd")
        self.assertEqual(ftp_service.version, "2.3.4")
        self.assertEqual(ftp_service.cpe, "cpe:/a:vsftpd:vsftpd:2.3.4")

    def test_generate_mock_scan(self):
        """Verifica que el escaneo simulado devuelva datos válidos y coherentes."""
        mock_report = generate_mock_scan()
        self.assertIsInstance(mock_report, ScanTargetReport)
        self.assertEqual(mock_report.target_ip, "192.168.1.50")
        self.assertEqual(len(mock_report.services), 5)

    def test_parse_nmap_scan_tool_invocation(self):
        """Prueba la herramienta de LangChain parse_nmap_scan_tool."""
        tool_output = parse_nmap_scan_tool.invoke({"scan_path_or_content": "mock"})
        data = json.loads(tool_output)
        self.assertIn("target_ip", data)
        self.assertIn("services", data)
        self.assertGreaterEqual(len(data["services"]), 1)


class TestCVSSCalculator(unittest.TestCase):

    def test_severity_levels(self):
        """Verifica la clasificación de severidad estándar CVSS v3.1."""
        self.assertEqual(get_severity_label(9.8), "CRITICAL")
        self.assertEqual(get_severity_label(8.5), "HIGH")
        self.assertEqual(get_severity_label(5.3), "MEDIUM")
        self.assertEqual(get_severity_label(2.1), "LOW")
        self.assertEqual(get_severity_label(0.0), "NONE")

    def test_impact_recommendations(self):
        """Verifica que cada nivel de severidad tenga una recomendación de urgencia."""
        self.assertIn("0-24 horas", get_impact_recommendation("CRITICAL"))
        self.assertIn("1-3 días", get_impact_recommendation("HIGH"))
        self.assertIn("1-2 semanas", get_impact_recommendation("MEDIUM"))

    def test_evaluate_vulnerability(self):
        """Verifica la estructura del objeto de vulnerabilidad evaluada."""
        result = evaluate_vulnerability(
            cve_id="CVE-2011-2523",
            cvss_score=9.8,
            description="vsftpd backdoor"
        )
        self.assertEqual(result.cve_id, "CVE-2011-2523")
        self.assertEqual(result.severity, "CRITICAL")
        self.assertEqual(result.cvss_score, 9.8)

    def test_cvss_evaluator_tool_invocation(self):
        """Prueba la herramienta de LangChain cvss_evaluator_tool."""
        sample_input = json.dumps([
            {"cve_id": "CVE-2018-15473", "cvss_score": 5.3, "description": "OpenSSH Enumeration"},
            {"cve_id": "CVE-2011-2523", "cvss_score": 9.8, "description": "vsftpd Backdoor"}
        ])
        output_str = cvss_evaluator_tool.invoke({"cves_json_input": sample_input})
        output_list = json.loads(output_str)

        # Debe ordenar de mayor a menor severidad
        self.assertEqual(len(output_list), 2)
        self.assertEqual(output_list[0]["cve_id"], "CVE-2011-2523")
        self.assertEqual(output_list[0]["severity"], "CRITICAL")
        self.assertEqual(output_list[1]["cve_id"], "CVE-2018-15473")


if __name__ == "__main__":
    unittest.main()
