import unittest

from pyaadhaar.decode import AadhaarSecureQr


def _is_version_header(header: bytes) -> bool:
    marker = header[:2].decode("ISO-8859-1", errors="ignore")
    return len(marker) == 2 and marker[0] == "V" and marker[1].isdigit()


class ParseVersionHeaderTests(unittest.TestCase):
    def test_v5_header(self):
        self.assertTrue(_is_version_header(b"V5\xff"))

    def test_v2_header(self):
        self.assertTrue(_is_version_header(b"V2\xff"))

    def test_legacy_header(self):
        self.assertFalse(_is_version_header(b"2\xff"))


class AadhaarSecureQrVersionLayoutTests(unittest.TestCase):
    def _decoder_with_header(self, header: bytes):
        decoder = AadhaarSecureQr.__new__(AadhaarSecureQr)
        decoder.decompressed_array = header
        decoder.details = [
            "email_mobile_status",
            "referenceid",
            "name",
            "dob",
            "gender",
            "careof",
            "district",
            "landmark",
            "house",
            "location",
            "pincode",
            "postoffice",
            "state",
            "street",
            "subdistrict",
            "vtc",
        ]
        decoder._check_for_version()
        return decoder

    def test_v5_adds_version_fields(self):
        decoder = self._decoder_with_header(b"V5\xff")
        self.assertEqual(decoder.details[0], "version")
        self.assertEqual(decoder.details[-1], "last_4_digits_mobile_no")

    def test_legacy_keeps_base_fields_only(self):
        decoder = self._decoder_with_header(b"2\xff")
        self.assertNotIn("version", decoder.details)
        self.assertNotIn("last_4_digits_mobile_no", decoder.details)


if __name__ == "__main__":
    unittest.main()
