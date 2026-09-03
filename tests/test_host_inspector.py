import unittest
from src.tools.host_inspector import (
    get_system_profile,
    inspect_listening_services,
    infer_service_from_port_and_process,
    run_active_host_diagnostics,
    HostEnvironmentProfile,
    LocalListeningService
)

class TestHostInspector(unittest.TestCase):

    def test_get_system_profile(self):
        """Verifica que se extraigan las variables de entorno y perfil del host correctamente."""
        profile = get_system_profile()
        self.assertIsInstance(profile, HostEnvironmentProfile)
        self.assertTrue(len(profile.hostname) > 0)
        self.assertIn(profile.os_name, ["Windows", "Linux", "Darwin"])
        self.assertTrue(len(profile.ip_addresses) >= 1)
        self.assertIsInstance(profile.safe_env_summary, dict)

    def test_infer_service_from_port(self):
        """Verifica la inferencia de servicios conocidos a partir de puertos y nombres de proceso."""
        svc, prod, cpe = infer_service_from_port_and_process(22, "sshd")
        self.assertEqual(svc, "ssh")
        self.assertIn("OpenSSH", prod)
        self.assertIsNotNone(cpe)

        svc, prod, cpe = infer_service_from_port_and_process(3306, "mysqld.exe")
        self.assertEqual(svc, "mysql")
        self.assertIn("MySQL", prod)

        svc, prod, cpe = infer_service_from_port_and_process(11434, "ollama.exe")
        self.assertEqual(svc, "ollama")

    def test_inspect_listening_services(self):
        """Verifica la inspección local de sockets en escucha de solo lectura."""
        services = inspect_listening_services()
        self.assertIsInstance(services, list)
        if services:
            s0 = services[0]
            self.assertIsInstance(s0, LocalListeningService)
            self.assertGreater(s0.port, 0)
            self.assertEqual(s0.protocol, "tcp")
            self.assertEqual(s0.status, "LISTEN")

    def test_run_active_host_diagnostics(self):
        """Verifica la integración completa del paquete de diagnóstico activo del host."""
        bundle = run_active_host_diagnostics()
        self.assertIn("target_ip", bundle)
        self.assertIn("hostname", bundle)
        self.assertIn("services", bundle)
        self.assertIn("host_profile", bundle)
        self.assertIn("raw_summary", bundle)
        self.assertGreaterEqual(bundle["open_ports_count"], 0)

if __name__ == "__main__":
    unittest.main()
