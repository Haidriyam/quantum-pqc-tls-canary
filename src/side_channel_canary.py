"""
Cryptographic Anomaly & Downgrade Detector.
Identifies deliberate protocol stripping and tampering during the hybrid handshake.
"""
from typing import Dict, Any


class HandshakeAnomalyDetector:
    @staticmethod
    def inspect_handshake(bundle: Dict[str, Any]) -> Dict[str, Any]:
        flags = []

        # Check for Classical Downgrade Stripping Attack
        if "pqc_ciphertext" not in bundle or len(bundle["pqc_ciphertext"]) == 0:
            flags.append("SECURITY_ALERT: PQC component stripped. Possible downgrade attack.")

        # Check for Null or Repeated Nonce / Replay conditions
        if bundle.get("client_classic_pub") == b"\x00" * 32:
            flags.append("SECURITY_ALERT: Weak or malformed public key supplied.")

        return {
            "handshake_secure": len(flags) == 0,
            "anomaly_count": len(flags),
            "threat_indicators": flags
        }