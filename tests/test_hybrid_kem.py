import unittest
from src.kem_hybrid import HybridPQCKeyExchange
from src.pqc_telemetry_gate import PQCProtocolCanaryGate


class TestHybridPQC(unittest.TestCase):

    def setUp(self):
        self.server_kem = HybridPQCKeyExchange()
        self.public_vector = self.server_kem.export_hybrid_public_key()

    def test_shared_secret_convergence(self):
        """Verify client and server arrive at mathematically identical hybrid secrets."""
        client_ss, bundle = HybridPQCKeyExchange.encapsulate(self.public_vector)
        server_ss = self.server_kem.decapsulate(bundle)

        self.assertEqual(len(client_ss), 48)  # SHA-384 output length
        self.assertEqual(client_ss, server_ss)

    def test_wire_overhead_profiling(self):
        _, bundle = HybridPQCKeyExchange.encapsulate(self.public_vector)
        metrics = PQCProtocolCanaryGate.audit_wire_overhead(bundle)

        self.assertEqual(metrics["classic_bytes"], 32)
        self.assertGreater(metrics["total_handshake_expansion_bytes"], 32)
        self.assertFalse(metrics["mtu_fragmentation_risk"])


if __name__ == "__main__":
    unittest.main()