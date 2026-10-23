import unittest

from triage.redaction import redact


class RedactionTests(unittest.TestCase):
    def check(self, text, expected, counts=None):
        out, got = redact(text)
        self.assertEqual(out, expected)
        if counts is not None:
            self.assertEqual(got, counts)

    def test_phone_formats(self):
        self.check("Call (555) 010-4477, 555.010.1234 or +1 555 010 9999.",
                   "Call [PHONE], [PHONE] or [PHONE].", {"PHONE": 3})

    def test_email(self):
        self.check("Write to jane.doe+clinic@example.org today", "Write to [EMAIL] today", {"EMAIL": 1})

    def test_ssn_and_dates(self):
        self.check("SSN 123-45-6789, DOB 03/14/1985, born March 14, 1985.",
                   "SSN [SSN], DOB [DATE], born [DATE].", {"SSN": 1, "DATE": 2})

    def test_cards_need_a_valid_checksum(self):
        self.check("4111 1111 1111 1111", "[CARD]", {"CARD": 1})
        self.check("1234 5678 9012 3456", "1234 5678 9012 3456", {})

    def test_record_identifiers(self):
        self.check("MRN: A1234567 and member id XZ-99881", "[ID] and [ID]", {"ID": 2})

    def test_leaves_ordinary_text_alone(self):
        text = "Room 12 at 10am on Thursday; take 2 pills twice a day."
        self.check(text, text, {})

    def test_redaction_is_idempotent(self):
        once, _ = redact("Call 555-010-2233 or mail a@b.co")
        twice, counts = redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(counts, {})
