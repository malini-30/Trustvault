"""Unit tests for encryption, upload validation and security helpers."""
import io
import unittest
import zipfile
from types import SimpleNamespace

from werkzeug.exceptions import BadRequest

from app import crypto, security
from app.seed import _pdf
from app.validation import UploadRejected, clean_filename, validate_upload

MB = 1024 * 1024


def office(kind="docx", extra=None, payload=b"<w:document/>"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml" if kind == "docx" else "xl/workbook.xml", payload)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class Crypto(unittest.TestCase):
    def setUp(self):
        self.key = crypto.derive_master_key("unit-test-master")

    def test_round_trip(self):
        blob, wrapped = crypto.encrypt_file(self.key, "doc-1", 1, b"secret")
        self.assertNotIn(b"secret", blob)
        self.assertEqual(crypto.decrypt_file(self.key, "doc-1", 1, blob, wrapped), b"secret")

    def test_ciphertext_is_bound_to_its_document_and_version(self):
        blob, wrapped = crypto.encrypt_file(self.key, "doc-1", 1, b"secret")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_file(self.key, "doc-2", 1, blob, wrapped)
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_file(self.key, "doc-1", 2, blob, wrapped)

    def test_tampering_and_wrong_master_key_are_detected(self):
        blob, wrapped = crypto.encrypt_file(self.key, "doc-1", 1, b"secret")
        flipped = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_file(self.key, "doc-1", 1, flipped, wrapped)
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_file(crypto.derive_master_key("other"), "doc-1", 1, blob, wrapped)

    def test_every_file_gets_a_fresh_key(self):
        a = crypto.encrypt_file(self.key, "d", 1, b"same")
        b = crypto.encrypt_file(self.key, "d", 1, b"same")
        self.assertNotEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])


class Validation(unittest.TestCase):
    def ok(self, name, data):
        return validate_upload(name, data, 10 * MB)

    def rejected(self, name, data, limit=10 * MB):
        with self.assertRaises(UploadRejected):
            validate_upload(name, data, limit)

    def test_accepts_real_files(self):
        self.assertEqual(self.ok("a.pdf", _pdf("hello")).mime, "application/pdf")
        self.assertEqual(self.ok("a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 20).extension, "png")
        self.assertEqual(self.ok("a.txt", "héllo".encode()).mime, "text/plain")
        self.assertEqual(self.ok("a.docx", office()).extension, "docx")
        self.assertEqual(self.ok("a.xlsx", office("xlsx")).extension, "xlsx")

    def test_extension_must_match_contents(self):
        self.rejected("invoice.pdf", b"MZ\x90\x00 windows executable")
        self.rejected("photo.png", _pdf("x"))
        self.rejected("notes.txt", b"\x89PNG\r\n\x1a\n0000")

    def test_markup_and_scripts_are_refused(self):
        self.rejected("page.html", b"<html><script>alert(1)</script></html>")
        self.rejected("logo.svg", b"<svg onload=alert(1)>")
        self.rejected("readme.txt", b"<!DOCTYPE html><script>alert(1)</script>")
        self.rejected("x.txt", b"<svg xmlns='http://www.w3.org/2000/svg'/>")

    def test_binary_or_invalid_text_is_refused(self):
        self.rejected("a.txt", b"abc\x00def")
        self.rejected("a.csv", b"\xff\xfe bad utf8")

    def test_active_pdf_content_is_refused(self):
        evil = _pdf("x").replace(b"/Type /Catalog", b"/Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >>")
        self.rejected("evil.pdf", evil)

    def test_truncated_pdf_is_refused(self):
        self.rejected("cut.pdf", _pdf("x")[:-20])

    def test_macro_documents_are_refused(self):
        self.rejected("macro.docx", office(extra={"word/vbaProject.bin": b"\x00" * 100}))

    def test_zip_bomb_is_refused(self):
        self.rejected("bomb.docx", office(payload=b"0" * (20 * MB)))

    def test_size_limit_and_empty(self):
        self.rejected("big.txt", b"a" * 101, limit=100)
        self.rejected("empty.txt", b"")

    def test_filenames_are_sanitised(self):
        self.assertEqual(clean_filename("../../etc/passwd.txt")[0], "passwd.txt")
        self.assertEqual(clean_filename("C:\\Users\\x\\report.pdf")[0], "report.pdf")
        name, ext = clean_filename("inv\u202eoice<script>.txt")
        self.assertNotIn("\u202e", name)
        self.assertNotIn("<", name)
        self.assertEqual(ext, "txt")
        with self.assertRaises(BadRequest):
            clean_filename("noextension")


class SecurityHelpers(unittest.TestCase):
    def test_password_hashing(self):
        h = security.hash_password("a long passphrase")
        self.assertTrue(security.verify_password("a long passphrase", h))
        self.assertFalse(security.verify_password("a long passphrasE", h))
        self.assertFalse(security.verify_password("x", "not-a-hash"))
        self.assertNotEqual(h, security.hash_password("a long passphrase"))  # salted

    def test_password_policy(self):
        self.assertIsNotNone(security.password_problem("short"))
        self.assertIsNone(security.password_problem("twelve chars!"))

    def test_uuid_check(self):
        self.assertTrue(security.is_uuid("5b6a1c8e-1234-4abc-8def-000000000000"))
        for bad in ("1", "' OR 1=1 --", "5b6a1c8e-1234-4abc-8def-00000000000", None, 7):
            self.assertFalse(security.is_uuid(bad))

    def test_client_ip_ignores_client_supplied_forwarded_entries(self):
        req = SimpleNamespace(headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"}, remote_addr="10.0.0.1")
        self.assertEqual(security.client_ip(req, 1), "203.0.113.9")  # appended by our proxy
        self.assertEqual(security.client_ip(req, 0), "10.0.0.1")

    def test_rate_limiter(self):
        rl = security.RateLimiter()
        self.assertTrue(all(rl.allow("k", 3) for _ in range(3)))
        self.assertFalse(rl.allow("k", 3))
        self.assertTrue(rl.allow("other", 3))
