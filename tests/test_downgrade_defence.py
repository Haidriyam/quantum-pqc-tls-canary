import unittest
from src.pqc_telemetry_gate import PQCProtocolCanaryGate
from src.side_channel_canary import HandshakeAnomalyDetector


class TestDowngradeResilience(unittest.TestCase):

    def test_legacy_suite_rejection(self):
        res = PQCProtocolCanaryGate.enforce_posture_policy("ECDHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(res["decision"], "BLOCKED")
        self.assertEqual(res["hndl_exposure_risk"], "HIGH_VULNERABILITY")

    def test_stripped_pqc_downgrade_detection(self):
        tampered_bundle = {
            "client_classic_pub": b"\x01" * 32,
            "pqc_ciphertext": b""
        }
        detection = HandshakeAnomalyDetector.inspect_handshake(tampered_bundle)
        self.assertFalse(detection["handshake_secure"])
        self.assertIn("SECURITY_ALERT: PQC component stripped", detection["threat_indicators"][0])


if __name__ == "__main__":
    unittest.main()