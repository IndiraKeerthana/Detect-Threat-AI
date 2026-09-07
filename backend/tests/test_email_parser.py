import unittest
from pathlib import Path

from app.services.email_parser import parse_email


class EmailParserTest(unittest.TestCase):
    def test_parse_email_fixture(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "sample.eml"

        result = parse_email(fixture.read_bytes())

        self.assertEqual(result.from_, "Alice Example <alice@example.com>")
        self.assertEqual(result.to, "Bob Example <bob@example.com>")
        self.assertEqual(result.cc, "Carol Example <carol@example.com>")
        self.assertEqual(result.bcc, "Secret Example <secret@example.com>")
        self.assertEqual(result.subject, "Controlled parser fixture")
        self.assertEqual(result.message_id, "<fixture-123@example.com>")
        self.assertEqual(
            result.received,
            [
                "from first.example (first.example [192.0.2.1]) by mx.example",
                "from second.example (second.example [192.0.2.2]) by first.example",
            ],
        )
        self.assertEqual(result.body_text, "Plain fixture body.")
        self.assertEqual(result.body_html, "<p>HTML fixture body.</p>")
        self.assertEqual(
            [attachment.model_dump() for attachment in result.attachments],
            [{"filename": "notes.txt", "content_type": "text/plain", "size": 18}],
        )
