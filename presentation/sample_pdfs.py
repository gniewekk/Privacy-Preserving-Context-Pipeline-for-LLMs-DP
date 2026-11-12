"""Generator poprawnych plików PDF (ISO 32000-1) do prezentacji CLI Osoby A."""

from __future__ import annotations

import zlib
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"


def _build_pdf_document(
    objects: list[bytes],
    *,
    root_obj: int = 1,
    info_obj: int | None = None,
) -> bytes:
    """Buduje poprawny plik PDF 1.4 z tablicą xref i trailerem."""
    chunks: list[bytes] = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    offsets: list[int] = [0]
    cursor = len(chunks[0])

    for index, body in enumerate(objects, start=1):
        offsets.append(cursor)
        obj_bytes = f"{index} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        chunks.append(obj_bytes)
        cursor += len(obj_bytes)

    xref_offset = cursor
    xref_lines = [f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")]
    for offset in offsets[1:]:
        xref_lines.append(f"{offset:010d} 00000 n \n".encode("ascii"))

    info_entry = f" /Info {info_obj} 0 R" if info_obj is not None else ""
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {root_obj} 0 R{info_entry} >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")

    chunks.extend(xref_lines)
    chunks.append(trailer)
    return b"".join(chunks)


def _make_text_invoice_pdf() -> bytes:
    content_stream = (
        b"BT\n"
        b"/F1 14 Tf\n"
        b"50 780 Td\n"
        b"(Faktura nr 7/2026) Tj\n"
        b"/F1 11 Tf\n"
        b"0 -26 Td\n"
        b"(Klient: Jan Kowalski, PESEL 44051401458, NIP 526-025-02-74) Tj\n"
        b"0 -18 Td\n"
        b"(IBAN PL61 1090 1014 0000 0712 1981 2874) Tj\n"
        b"0 -18 Td\n"
        b"(Telefon: 534595825, Adres: ul. Lipowa 12) Tj\n"
        b"0 -18 Td\n"
        b"(Email: jan.kowalski@example.com) Tj\n"
        b"ET"
    )
    compressed_content = zlib.compress(content_stream)

    xmp_stream = (
        b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        b'  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        b'    <rdf:Description rdf:about="">'
        b"Ukryte XMP: Piotr Zielinski 44051401458"
        b"</rdf:Description>\n"
        b"  </rdf:RDF>\n"
        b"</x:xmpmeta>\n"
        b'<?xpacket end="w"?>'
    )

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (
            f"<< /Filter /FlateDecode /Length {len(compressed_content)} >>\nstream\n".encode(
                "ascii"
            )
            + compressed_content
            + b"\nendstream"
        ),
        (
            f"<< /Type /Metadata /Subtype /XML /Length {len(xmp_stream)} >>\nstream\n".encode(
                "ascii"
            )
            + xmp_stream
            + b"\nendstream"
        ),
        b"<< /Author (Tajny Autor Anna Nowak) /Title (Poufna Faktura 7/2026) >>",
    ]
    return _build_pdf_document(objects, root_obj=1, info_obj=7)


def _make_scanned_image_pdf() -> bytes:
    width = 240
    height = 80
    rows: list[bytes] = []
    for y in range(height):
        if y in (0, height - 1) or 20 <= y <= 24 or 42 <= y <= 46:
            row = b"\x33\x33\x33" * width
        else:
            row = b"\xf5\xf5\xf5" * width
        rows.append(row)
    compressed_image = zlib.compress(b"".join(rows))

    draw_stream = b"q\n440 0 0 140 77 620 cm\n/Im1 Do\nQ"
    compressed_draw = zlib.compress(draw_stream)

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        (
            f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode "
            f"/Length {len(compressed_image)} >>\nstream\n".encode("ascii")
            + compressed_image
            + b"\nendstream"
        ),
        (
            f"<< /Filter /FlateDecode /Length {len(compressed_draw)} >>\nstream\n".encode(
                "ascii"
            )
            + compressed_draw
            + b"\nendstream"
        ),
    ]
    return _build_pdf_document(objects, root_obj=1)


def ensure_sample_pdfs(output_dir: Path = SAMPLES_DIR) -> tuple[Path, Path]:
    """Tworzy dwa poprawne, otwieralne w przeglądarce PDF pliki demonstracyjne.

    1. `faktura_tekstowa.pdf` — poprawny PDF 1.4 z warstwą tekstową (FlateDecode),
       słownikiem `/Info` (/Author, /Title) oraz strumieniem XMP `/Metadata`.
    2. `skan_bez_ocr.pdf` — poprawny PDF 1.4 zawierający wyłącznie obraz rastrowy
       (`/Subtype /Image`) bez warstwy tekstowej, demonstrujący blokadę `STRICT_NO_OCR`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    text_pdf_path = output_dir / "faktura_tekstowa.pdf"
    text_pdf_path.write_bytes(_make_text_invoice_pdf())

    scan_pdf_path = output_dir / "skan_bez_ocr.pdf"
    scan_pdf_path.write_bytes(_make_scanned_image_pdf())

    return text_pdf_path, scan_pdf_path
