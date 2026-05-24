"""Integration tests using synthetic QR payloads only — never commit real Aadhaar data."""

import unittest
import zlib
from io import BytesIO

from PIL import Image

from pyaadhaar.decode import AadhaarSecureQr

_SIGNATURE_BYTES = 256


def _build_synthetic_v5_decompressed(*, include_photo: bool) -> bytes:
    segments = [
        "V5",
        "2",
        "000000000000000000000",
        "Synthetic Test User",
        "01-01-1990",
        "M",
        "C/O: Synthetic",
        "TestDistrict",
        "",
        "1 Test Street",
        "",
        "000000",
        "TestPO",
        "TestState",
        "TestStreet",
        "TestSubdist",
        "TestVTC",
        "XXXXXX0000",
    ]
    buf = bytearray()
    for segment in segments:
        buf.extend(segment.encode("ISO-8859-1"))
        buf.append(255)
    if include_photo:
        photo_buf = BytesIO()
        Image.new("RGB", (1, 1), color="red").save(photo_buf, format="JPEG")
        buf.extend(photo_buf.getvalue())
    buf.extend(b"\x00" * _SIGNATURE_BYTES)
    return bytes(buf)


def _qr_int_from_decompressed(decompressed: bytes) -> int:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    compressed = compressor.compress(decompressed) + compressor.flush()
    return int.from_bytes(compressed, "big")


class V5SecureQrIntegrationTests(unittest.TestCase):
    def test_decode_synthetic_v5_fields(self):
        raw = _build_synthetic_v5_decompressed(include_photo=True)
        decoder = AadhaarSecureQr(_qr_int_from_decompressed(raw))
        data = decoder.decodeddata()
        self.assertEqual(data.get("version"), "V5")
        self.assertEqual(data.get("name"), "Synthetic Test User")
        self.assertEqual(data.get("aadhaar_last_4_digit"), "0000")

    def test_synthetic_v5_without_photo_has_no_image(self):
        raw = _build_synthetic_v5_decompressed(include_photo=False)
        decoder = AadhaarSecureQr(_qr_int_from_decompressed(raw))
        self.assertFalse(decoder.isImage())


if __name__ == "__main__":
    unittest.main()
