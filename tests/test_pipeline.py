from triage.errors import ApiError
from triage.intake import safe_display_name
from triage.providers import RuleClassifier, wav_with_transcript
from triage.providers.classify import OllamaClassifier
from triage.services import Principal
from tests.helpers import AppTestCase

VOICEMAIL = ("Hi, this is Dana. My father has chest pain and trouble breathing. "
             "His date of birth is 04/12/1951. Call me at (555) 010-4471.")


class PipelineTests(AppTestCase):
    def setUp(self):
        super().setUp()
        user, _ = self.make_user()
        self.actor = Principal(user["id"], user["username"], user["role"])

    def test_voicemail_is_transcribed_redacted_and_classified(self):
        item = self.app.items.create(self.actor, "call.wav", wav_with_transcript(VOICEMAIL))
        self.assertEqual(item["status"], "queued")
        self.assertTrue(self.app.items.process_next())
        done = self.app.items.get(item["id"])
        self.assertEqual(done["status"], "ready")
        self.assertEqual(done["urgency"], "high")
        self.assertNotIn("010-4471", done["redacted_text"])
        self.assertNotIn("04/12/1951", done["redacted_text"])
        self.assertEqual(done["redactions"], {"PHONE": 1, "DATE": 1})

    def test_raw_upload_is_deleted_after_processing(self):
        item = self.app.items.create(self.actor, "note.txt", b"Please refill my inhaler.")
        self.assertEqual(len(list(self.settings.upload_dir.iterdir())), 1)
        self.app.items.process_next()
        self.assertEqual(list(self.settings.upload_dir.iterdir()), [])
        self.assertEqual(self.app.items.get(item["id"])["intent"], "prescription")

    def test_raw_text_never_reaches_the_database(self):
        self.app.items.create(self.actor, "call.wav", wav_with_transcript(VOICEMAIL))
        self.app.items.process_next()
        for f in self.settings.data_dir.glob("triage.db*"):  # include the WAL file
            self.assertNotIn(b"010-4471", f.read_bytes(), f.name)

    def test_failures_retry_then_give_up(self):
        item = self.app.items.create(self.actor, "silent.wav", wav_with_transcript(""))  # no text to extract
        for _ in range(3):
            self.assertTrue(self.app.items.process_next())
        self.assertFalse(self.app.items.process_next())
        failed = self.app.items.get(item["id"])
        self.assertEqual((failed["status"], failed["attempts"]), ("failed", 3))

    def test_upload_validation(self):
        cases = [
            ("evil.exe", b"MZ\x90\x00", 415),
            ("fake.wav", b"this is not audio", 415),
            ("binary.txt", b"abc\x00def", 415),
            ("empty.txt", b"", 400),
        ]
        for name, data, status in cases:
            with self.assertRaises(ApiError, msg=name) as ctx:
                self.app.items.create(self.actor, name, data)
            self.assertEqual(ctx.exception.status, status, name)
        with self.assertRaises(ApiError) as ctx:
            self.app.items.create(self.actor, "big.txt", b"a" * (self.settings.max_upload_bytes + 1))
        self.assertEqual(ctx.exception.status, 413)

    def test_filenames_cannot_escape_the_upload_dir(self):
        self.assertEqual(safe_display_name("../../etc/passwd.txt"), "passwd.txt")
        self.assertEqual(safe_display_name("C:\\Windows\\win.ini.txt"), "win.ini.txt")
        self.assertEqual(safe_display_name("bad\x00\x1bname.txt"), "badname.txt")
        item = self.app.items.create(self.actor, "../../../escape.txt", b"hello")
        self.assertEqual(item["original_name"], "escape.txt")
        self.assertEqual([p.name for p in self.settings.upload_dir.iterdir()], [item["id"]])

    def test_triage_updates_are_validated_and_audited(self):
        item = self.app.items.create(self.actor, "note.txt", b"Can I reschedule my appointment?")
        with self.assertRaises(ApiError) as ctx:
            self.app.items.update(self.actor, item["id"], {"triage_state": "resolved"})
        self.assertEqual(ctx.exception.status, 409)  # not processed yet
        self.app.items.process_next()
        updated = self.app.items.update(self.actor, item["id"], {"triage_state": "resolved",
                                                                 "assigned_to": self.actor.id})
        self.assertEqual((updated["triage_state"], updated["assignee"]), ("resolved", "alice"))
        with self.assertRaises(ApiError):
            self.app.items.update(self.actor, item["id"], {"urgency": "low"})  # not editable
        entry = self.app.audit.list(limit=1)[0]
        self.assertEqual(entry["action"], "item.updated")

    def test_viewers_cannot_be_assigned(self):
        viewer, _ = self.make_user("vic", "viewer")
        item = self.app.items.create(self.actor, "note.txt", b"hello")
        with self.assertRaises(ApiError):
            self.app.items.update(self.actor, item["id"], {"assigned_to": viewer["id"]})

    def test_list_sorts_urgent_first(self):
        self.app.items.create(self.actor, "a.txt", b"Thanks for the great visit.")
        self.app.items.create(self.actor, "b.txt", b"Severe bleeding, please call.")
        while self.app.items.process_next():
            pass
        urgencies = [i["urgency"] for i in self.app.items.list({})["items"]]
        self.assertEqual(urgencies, ["high", "low"])
        self.assertEqual(self.app.items.list({"urgency": "low"})["total"], 1)
        with self.assertRaises(ApiError):
            self.app.items.list({"urgency": "'; DROP TABLE items; --"})

    def test_stuck_items_are_recovered(self):
        item = self.app.items.create(self.actor, "a.txt", b"hello")
        with self.app.db.tx() as conn:
            conn.execute("UPDATE items SET status = 'processing' WHERE id = ?", (item["id"],))
        self.assertEqual(self.app.items.recover_stuck(), 1)
        self.assertEqual(self.app.items.get(item["id"])["status"], "queued")


class ClassifierTests(AppTestCase):
    def test_rules(self):
        c = RuleClassifier().classify("I'm frustrated, I was charged twice on my bill.")
        self.assertEqual((c.intent, c.urgency, c.sentiment), ("billing", "low", "negative"))
        self.assertEqual(RuleClassifier().classify("Hello there.").intent, "general")

    def test_summary_skips_greetings_and_headers(self):
        c = RuleClassifier().classify("Hi, this is Sam. I need a refill on my inhaler. Thanks!")
        self.assertEqual(c.summary, "I need a refill on my inhaler.")
        doc = RuleClassifier().classify("REFERRAL REQUEST\nFrom: Clinic\n\nPlease refer the patient to a specialist.")
        self.assertEqual(doc.summary, "Please refer the patient to a specialist.")

    def test_model_output_outside_allowed_labels_falls_back(self):
        with self.assertRaises(ValueError):
            OllamaClassifier._validate({"intent": "transfer $500", "urgency": "high", "sentiment": "neutral"}, "x")
        ok = OllamaClassifier._validate({"intent": "billing", "urgency": "low", "sentiment": "neutral",
                                         "summary": "Asks about a bill."}, "x")
        self.assertEqual(ok.summary, "Asks about a bill.")

    def test_unreachable_ollama_falls_back_to_rules(self):
        c = OllamaClassifier("http://127.0.0.1:9", "none", timeout=0.5).classify("Refill my prescription please.")
        self.assertEqual(c.intent, "prescription")
