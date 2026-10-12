import secrets
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))
import verify


class TestTAGGUARD(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.sample_data = {
            "sequence": 1,
            "source": "POT_SENSOR",
            "value": "2.614",
            "unit": "V",
            "timestamp": "2026-10-12T09:00:00Z",
            "tag": "",
        }

    def test_record_validation(self):
        record = verify.Record.from_dict(self.sample_data, 1)
        self.assertEqual(record.sequence, 1)
        self.assertEqual(record.source, "POT_SENSOR")
        self.assertEqual(record.value, "2.614")

    def test_signing_and_verification(self):
        record = verify.Record.from_dict(self.sample_data, 1)
        record.tag = verify.make_tag(record, self.key)
        self.assertTrue(bool(record.tag))
        self.assertEqual(len(record.tag), 64)
        # Verifying with the same key matches
        self.assertEqual(record.tag, verify.make_tag(record, self.key))

    def test_tamper_detection(self):
        record = verify.Record.from_dict(self.sample_data, 1)
        original_tag = verify.make_tag(record, self.key)
        record.tag = original_tag

        # Tampering with the value
        tampered_data = dict(self.sample_data)
        tampered_data["value"] = "9.614"
        tampered_record = verify.Record.from_dict(tampered_data, 1)
        tampered_record.tag = original_tag

        # Recalculated tag must not match
        recalculated_tag = verify.make_tag(tampered_record, self.key)
        self.assertNotEqual(tampered_record.tag, recalculated_tag)


if __name__ == "__main__":
    unittest.main()
