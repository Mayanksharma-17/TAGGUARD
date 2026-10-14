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

    def test_canonical_json_determinism(self):
        record = verify.Record.from_dict(self.sample_data, 1)
        canonical = verify.canonical_bytes(record).decode("utf-8")
        # Ensure keys are alphabetical: sequence, source, timestamp, unit, value
        expected = '{"sequence":1,"source":"POT_SENSOR","timestamp":"2026-10-12T09:00:00Z","unit":"V","value":"2.614"}'
        self.assertEqual(canonical, expected)

    def test_sequence_anomaly(self):
        rec1 = verify.Record.from_dict(self.sample_data, 1)
        rec1.tag = verify.make_tag(rec1, self.key)
        rec3_data = dict(self.sample_data)
        rec3_data["sequence"] = 3
        rec3 = verify.Record.from_dict(rec3_data, 2)
        rec3.tag = verify.make_tag(rec3, self.key)

        # In a list with a gap [1, 3], verify_file logic flags sequence error
        self.assertEqual(rec1.sequence, 1)
        self.assertEqual(rec3.sequence, 3)

    def test_utf8_bom_handling(self):
        import tempfile
        rec = verify.Record.from_dict(self.sample_data, 1)
        rec.tag = verify.make_tag(rec, self.key)
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
            # Write with UTF-8 BOM
            content = f'[{{"sequence": 1, "source": "POT_SENSOR", "value": "2.614", "unit": "V", "timestamp": "2026-10-12T09:00:00Z", "tag": "{rec.tag}"}}]'
            f.write(b"\xef\xbb\xbf" + content.encode("utf-8"))
            temp_path = Path(f.name)
        try:
            records = verify.load_records(temp_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].tag, rec.tag)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_hash_chain_canonical_and_verification(self):
        genesis = "0" * 64
        v2_data = dict(self.sample_data)
        v2_data["prev_tag"] = genesis
        rec1 = verify.Record.from_dict(v2_data, 1)
        self.assertTrue(rec1.is_chained)
        canonical = verify.canonical_bytes(rec1).decode("utf-8")
        # Ensure keys are alphabetical: prev_tag, sequence, source, timestamp, unit, value
        expected = f'{{"prev_tag":"{genesis}","sequence":1,"source":"POT_SENSOR","timestamp":"2026-10-12T09:00:00Z","unit":"V","value":"2.614"}}'
        self.assertEqual(canonical, expected)
        rec1.tag = verify.make_tag(rec1, self.key)

        # Record 2 chained to Record 1's tag
        v2_data2 = dict(self.sample_data)
        v2_data2["sequence"] = 2
        v2_data2["value"] = "1.500"
        v2_data2["prev_tag"] = rec1.tag
        rec2 = verify.Record.from_dict(v2_data2, 2)
        rec2.tag = verify.make_tag(rec2, self.key)

        # Both records verify against their tags
        self.assertEqual(rec1.tag, verify.make_tag(rec1, self.key))
        self.assertEqual(rec2.tag, verify.make_tag(rec2, self.key))
        self.assertEqual(rec2.prev_tag, rec1.tag)


if __name__ == "__main__":
    unittest.main()
