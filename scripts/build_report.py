import json
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
BLUE = colors.HexColor("#17466D")
LIGHT = colors.HexColor("#EDF3F8")


def main():
    benchmark = json.loads((ROOT / "test_cases/benchmarks/summary.json").read_text())
    scenarios = json.loads((ROOT / "test_cases/results/scenarios.json").read_text())
    container = json.loads((ROOT / "test_cases/container-local/summary.json").read_text())
    suites = ET.parse(ROOT / "test_cases/results/pytest.xml").getroot().findall("testsuite")
    tests = sum(int(suite.attrib["tests"]) for suite in suites)
    failures = sum(int(suite.attrib["failures"]) + int(suite.attrib["errors"]) for suite in suites)
    environment = benchmark["environment"]
    sections = [
        (
            "1. Pendahuluan",
            "AntiCNSpy merupakan kakas CLI untuk penandatanganan dan verifikasi rilis "
            "perangkat lunak. Rancangan mengadaptasi alur penandatanganan blob pada Sigstore "
            "Cosign: artefak di-hash, informasinya dibentuk sebagai manifest, kemudian "
            "manifest ditandatangani. Implementasi "
            "alur aplikasi, format, validasi, serta trust store dilakukan dalam program sendiri. "
            "Cosign tidak digunakan sebagai pengganti implementasi. "
            "Kepercayaan dikelola secara lokal "
            "dan eksplisit, tanpa sertifikat atau transparency log.",
        ),
        (
            "2. Dasar teori",
            "Tanda tangan digital memungkinkan pemeriksaan integritas pesan dan kepemilikan kunci "
            "privat yang sesuai dengan kunci publik. Hash SHA-256 artefak mengikat isi berkas, "
            "sedangkan tanda tangan atas seluruh manifest mengikat paket, versi, profil, keyid, "
            "nama berkas, ukuran, dan hash. RSA-PSS menggunakan padding probabilistik; ECDSA "
            "menggunakan operasi kurva P-256 dengan nonce aman; Ed25519 menggunakan PureEdDSA "
            "secara deterministik. Keabsahan matematis tanda tangan tidak dengan sendirinya "
            "memberi kepercayaan kepada penerbit atau menjamin perangkat lunak bebas malware.",
        ),
        (
            "3. Perancangan sistem",
            "Program memisahkan CLI, format, artefak, kunci, operasi kriptografi, trust store, "
            "penandatanganan, dan verifikasi. Manifest dibentuk dalam urutan field tetap dan "
            "UTF-8 tanpa BOM/spasi/baris baru. Bundle menyimpan byte manifest serta tanda tangan "
            "dalam Base64 standar. Parser mendeteksi field duplikat saat parsing, menolak field "
            "tambahan dan tipe yang salah, lalu membandingkan serialisasi canonical dengan byte "
            "asli. Tanda tangan selalu diperiksa terhadap byte asli yang tersimpan.",
        ),
        (
            "4. Implementasi dan simulasi",
            "Implementasi menggunakan Python dan cryptography 50.0.2. CLI menggunakan argparse; "
            "JSON, Base64, hashing, dan penulisan atomik menggunakan pustaka standar. Kunci privat "
            "berformat PKCS8 PEM dan kunci publik SPKI PEM. Fingerprint dihitung dari SHA-256 "
            "DER SPKI hasil ekspor ulang. Profil RSA menggunakan modulus 3072 bit, eksponen 65537, "
            "SHA-256/MGF1-SHA-256 dan salt tepat 32 byte. ECDSA menggunakan P-256/SHA-256 dan "
            "mengubah keluaran DER menjadi r || s, masing-masing 32 byte big-endian. Ed25519 "
            "menerima byte manifest secara langsung tanpa prehash eksternal.",
        ),
        (
            "5. Pengujian fungsional dan interoperabilitas",
            f"Snapshot pengujian mencatat {tests} pengujian pytest "
            f"dengan {failures} kegagalan/error "
            f"serta {len(scenarios['cases'])} skenario bukti U01-U14 yang seluruhnya lulus. U01 "
            "menguji teks, biner dan berkas kosong pada ketiga profil. U14 menandatangani manifest "
            "identik dua kali: RSA-PSS dan ECDSA menghasilkan tanda tangan berbeda; Ed25519 "
            "menghasilkan tanda tangan identik; keduanya tetap lolos verifikasi. OpenSSL CLI "
            "digunakan sebagai kakas eksternal untuk menguji kedua arah interoperabilitas pada "
            "semua profil, dengan konversi DER/raw pada ECDSA. Bukti ini tidak menyatakan "
            "independensi backend kriptografi, karena pustaka Python juga menggunakan OpenSSL.",
        ),
        (
            "6. Distribusi dan integrasi CI/CD",
            "Image Linux/amd64 telah dibangun dan diuji secara lokal. Image mengemas seluruh "
            "dependensi, menggunakan entrypoint CLI, dan mendukung jaringan dinonaktifkan, "
            "bind mount serta identitas nonroot. Kunci privat CI terpisah dari fixture publik, "
            "diberikan melalui secret, di-mount read-only hanya saat sign, dan dibersihkan. "
            "Verifikasi menggunakan trust store publik yang disiapkan independen. Harness "
            "menyimpan exit code asli, hasil JSON dan keberadaan marker deployment. Publikasi "
            "image publik dan workflow hosted belum dijalankan; hasil lokal secara eksplisit "
            "ditandai registry_pull=false dan tidak menggantikan bukti registry-pull.",
        ),
        (
            "7. Analisis keamanan",
            "Modifikasi artefak ditolak melalui ukuran/hash; modifikasi manifest/tanda tangan "
            "ditolak sebelum metadata diperiksa. Kepercayaan memerlukan kecocokan keyid, profil "
            "dan izin paket yang diharapkan pengguna. Semua entri trust store divalidasi. "
            "Kunci privat tidak dimasukkan ke bundle, image atau log. Berkas privat Unix memakai "
            "mode 0600; penimpaan memerlukan opsi eksplisit. Nonce ECDSA dan salt RSA menggunakan "
            "CSPRNG backend. Pembaruan trust store memakai temporary file yang di-flush/fsync "
            "dan diganti secara atomik. Penulisan bersamaan tetap memerlukan locking eksternal. "
            "Penghapusan kunci berlaku berdasarkan trust store saat verifikasi. Pencegahan "
            "rollback otomatis memerlukan trusted state tambahan; versi harapan dari caller "
            "hanya menolak rilis yang berbeda dari versi tersebut.",
        ),
        (
            "8. Pengukuran performa",
            "Artefak deterministik berukuran 1 KiB, 1 MiB dan 16 MiB digunakan sama pada seluruh "
            "profil. Pembangkitan kunci diukur 5 kali per algoritma. "
            "Setiap metrik sign/verify/hash "
            "menggunakan 5 warm-up dan 30 pengulangan terukur dengan perf_counter_ns. Median "
            "dan P95 nearest-rank dihitung dari sampel mentah; P95 adalah elemen ceil(0.95*n) "
            "pada urutan naik dengan indeks mulai 1. Hash artefak di memori diukur terpisah. "
            "Operasi crypto atas manifest mencakup hash internal algoritma, "
            "tanpa I/O/hash artefak. "
            "Pengukuran CLI mencakup proses Python baru, parsing, I/O, hash dan keluaran. "
            "Hasil adalah snapshot lingkungan lokal; proses latar belakang dapat menimbulkan "
            "noise dan angka tidak mewakili seluruh perangkat atau pipeline.",
        ),
        (
            "9. Kesimpulan dan pengembangan",
            "Fungsi wajib lokal telah diimplementasikan dan bukti pengujian menunjukkan penolakan "
            "yang sesuai untuk skenario manipulasi, kesalahan format dan kepercayaan. Pemisahan "
            "manifest, bundle dan trust store menjaga batas antara integritas data dan "
            "otorisasi penerbit. Langkah penyelesaian eksternal adalah publikasi image/tag, "
            "pencatatan digest yang sebenarnya, penyiapan secret GitHub, dan pengambilan bukti "
            "workflow registry consumer. Identitas/foto anggota serta pembagian tugas menunggu "
            "data pengguna. Pengembangan berikutnya dapat mencakup penyimpanan kunci terenkripsi, "
            "freshness policy, locking trust store dan layanan timestamp.",
        ),
    ]
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle("TextBody", fontName="Helvetica", fontSize=9.5, leading=14, spaceAfter=9)
    )
    styles.add(ParagraphStyle("SmallCell", fontName="Helvetica", fontSize=7.4, leading=10))
    styles.add(
        ParagraphStyle(
            "CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=34,
            leading=40,
            textColor=BLUE,
            alignment=TA_CENTER,
            spaceAfter=20,
        )
    )
    styles["Heading1"].textColor = BLUE
    styles["Heading1"].fontSize = 15
    styles["Heading1"].leading = 19
    width = A4[0] - 38 * mm
    story = []
    markdown = [
        "# AntiCNSpy - laporan teknis (DRAF)",
        "",
        "Identitas, foto anggota, dan pembagian tugas akan diberikan kemudian.",
        "Bantuan AI digunakan sesuai izin yang dikonfirmasi pengguna.",
        "",
    ]

    def p(value, style="TextBody"):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])

    def paragraph(value):
        story.append(p(value))
        markdown.extend([value, ""])

    def table(headers, rows, fractions=None):
        data = [[p(value, "SmallCell") for value in row] for row in [headers, *rows]]
        col_widths = [width / len(headers)] * len(headers)
        if fractions:
            col_widths = [width * fraction for fraction in fractions]
        block = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        block.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C3D1DD")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.extend([block, Spacer(1, 10)])
        markdown.append("| " + " | ".join(headers) + " |")
        markdown.append("| " + " | ".join(["---"] * len(headers)) + " |")
        markdown.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
        markdown.append("")

    def diagram(labels):
        drawing = Drawing(width, 65)
        box = (width - 3 * 15) / 4
        for i, label in enumerate(labels):
            x = i * (box + 15)
            drawing.add(Rect(x, 15, box, 38, rx=4, ry=4, fillColor=LIGHT, strokeColor=BLUE))
            drawing.add(
                String(
                    x + box / 2,
                    31,
                    label,
                    textAnchor="middle",
                    fontName="Helvetica",
                    fontSize=8,
                    fillColor=BLUE,
                )
            )
            if i < 3:
                drawing.add(Line(x + box, 34, x + box + 13, 34, strokeColor=BLUE))
                drawing.add(
                    Polygon(
                        [x + box + 13, 34, x + box + 9, 37, x + box + 9, 31],
                        fillColor=BLUE,
                        strokeColor=BLUE,
                    )
                )
        story.append(drawing)

    story.extend(
        [
            Spacer(1, 55 * mm),
            p("AntiCNSpy", "CoverTitle"),
            p("Penandatanganan dan Verifikasi Software Release", "Title"),
            Spacer(1, 12 * mm),
            p("Tugas 3 IF4020 Kriptografi | 2026/2027", "Heading2"),
            p("DRAF TEKNIS - identitas dan foto anggota menyusul"),
            p("Versi program 1.0.0 | Disusun 15 November 2026 (WIB)"),
            p(
                "Laporan memuat hasil pengujian nyata. Publikasi registry dan bukti workflow "
                "hosted masih menunggu pelaksanaan."
            ),
            p("Bantuan AI digunakan sesuai izin yang dikonfirmasi pengguna."),
            PageBreak(),
        ]
    )
    for heading, body in sections:
        story.append(KeepTogether([p(heading, "Heading1"), p(body)]))
        markdown.extend(["## " + heading, "", body, ""])
        if heading.startswith("3."):
            diagram(["Artefak", "Manifest", "Sign", "Bundle"])
            diagram(["Format + trust", "Signature", "Metadata + hash", "Terima / tolak"])
            table(
                ["Urutan", "Kegagalan", "Exit"],
                [
                    [1, "INPUT_ERROR", 2],
                    [2, "FORMAT_ERROR", 1],
                    [3, "UNSUPPORTED_ALGORITHM", 1],
                    [4, "KEY_NOT_TRUSTED", 1],
                    [5, "INVALID_SIGNATURE", 1],
                    [6, "METADATA_MISMATCH", 1],
                    [7, "ARTIFACT_MISMATCH", 1],
                    [8, "OK", 0],
                ],
                [0.13, 0.72, 0.15],
            )
        elif heading.startswith("5."):
            table(
                ["Skenario", "Hasil aktual", "Lulus"],
                [
                    [case["id"], case["result"]["status"], str(case["passed"])]
                    for case in scenarios["cases"]
                ],
                [0.50, 0.36, 0.14],
            )
        elif heading.startswith("6."):
            table(
                ["Skenario", "Profil / kondisi", "Hasil lokal"],
                [
                    [
                        case["id"],
                        case.get("algorithm", "offline/nonroot/no TTY"),
                        case.get("actual_status", "OK") + " / " + str(case["passed"]),
                    ]
                    for case in container["cases"]
                ],
                [0.14, 0.43, 0.43],
            )
        elif heading.startswith("8."):
            paragraph(
                "Lingkungan: "
                + environment["platform"]
                + "; "
                + environment["cpu"]
                + f"; {environment['logical_cpus']} logical CPU; Python "
                + environment["python"].split(" (")[0]
                + "; cryptography "
                + environment["cryptography"]
                + "; backend "
                + environment["openssl_backend"]
            )
            timings = benchmark["timings"]

            def timing(algorithm, size, metric, statistic="median_ns", rows=timings):
                row = next(
                    r
                    for r in rows
                    if r["algorithm"] == algorithm
                    and r["artifact_bytes"] == size
                    and r["metric"] == metric
                )
                return f"{row[statistic] / 1e6:.5f}"

            profiles = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
            unique_sizes = sorted({r["artifact_bytes"] for r in benchmark["sizes"]})
            table(
                ["Profil", "Keygen median (ms)", "Publik DER", "Privat DER", "Signature"],
                [
                    [
                        algorithm,
                        timing(algorithm, None, "keygen"),
                        *[
                            next(r for r in benchmark["sizes"] if r["algorithm"] == algorithm)[
                                field
                            ]
                            for field in (
                                "public_key_der_bytes",
                                "private_key_der_bytes",
                                "signature_bytes",
                            )
                        ],
                    ]
                    for algorithm in profiles
                ],
                [0.28, 0.25, 0.16, 0.16, 0.15],
            )
            paragraph("Operasi kriptografi atas manifest (seluruh waktu dalam milidetik):")
            table(
                ["Profil / byte artefak", "Sign median", "Sign P95", "Verify median", "Verify P95"],
                [
                    [
                        f"{algorithm} / {size}",
                        timing(algorithm, size, "crypto_sign"),
                        timing(algorithm, size, "crypto_sign", "p95_ns"),
                        timing(algorithm, size, "crypto_verify"),
                        timing(algorithm, size, "crypto_verify", "p95_ns"),
                    ]
                    for algorithm in profiles
                    for size in unique_sizes
                ],
                [0.36, 0.16, 0.16, 0.16, 0.16],
            )
            story.append(PageBreak())
            paragraph("Pengukuran aplikasi lengkap (milidetik, termasuk startup/I/O/hash):")
            table(
                ["Profil / byte artefak", "Sign median", "Sign P95", "Verify median", "Verify P95"],
                [
                    [
                        f"{algorithm} / {size}",
                        timing(algorithm, size, "cli_sign"),
                        timing(algorithm, size, "cli_sign", "p95_ns"),
                        timing(algorithm, size, "cli_verify"),
                        timing(algorithm, size, "cli_verify", "p95_ns"),
                    ]
                    for algorithm in profiles
                    for size in unique_sizes
                ],
                [0.36, 0.16, 0.16, 0.16, 0.16],
            )
            paragraph(
                "Ukuran bundle/manifest dan hash artefak lengkap tersedia dalam "
                "test_cases/benchmarks/summary.json; seluruh sampel dalam raw.csv. "
                "Waktu crypto tidak bertambah sebanding ukuran artefak karena pesan yang "
                "ditandatangani adalah manifest yang kecil. Waktu aplikasi juga mencakup "
                "pembacaan dan hashing artefak; jangan menyimpulkan performa crypto dari "
                "waktu CLI saja."
            )
    story.append(p("10. Referensi dan lampiran", "Heading1"))
    markdown.extend(["## 10. Referensi dan lampiran", ""])
    for reference in [
        "Spesifikasi Tugas3-nOinject.pdf, bagian 2.1-2.9 dan 3.1.",
        "RFC 8017 (RSA-PSS); RFC 6979 (ECDSA nonce deterministik); RFC 8032 (Ed25519).",
        "RFC 8410 (SPKI Ed25519); RFC 4648 (Base64); RFC 5958 (kunci asimetris).",
        "Dokumentasi cryptography: https://cryptography.io/en/stable/",
        "Dokumentasi Python JSON: https://docs.python.org/3/library/json.html",
        "Source: https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi",
        "Reproduksi: python -m pytest; python scripts/run_evidence.py; python benchmarks/run.py.",
        "Bukti: test_cases/results, fixtures, benchmarks dan container-local. "
        "Perintah aktual serta hasil yang diharapkan dicatat dalam setiap case.json.",
        "Tautan workflow hosted, digest publik, foto/identitas "
        "dan tabel pembagian tugas: menyusul.",
    ]:
        paragraph(reference)

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(BLUE)
        canvas.line(19 * mm, 17 * mm, A4[0] - 19 * mm, 17 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(BLUE)
        canvas.drawString(19 * mm, 12 * mm, "AntiCNSpy | IF4020 | Draf teknis")
        canvas.drawRightString(A4[0] - 19 * mm, 12 * mm, f"Halaman {document.page}")
        canvas.restoreState()

    destination = ROOT / "output/pdf/AntiCNSpy-technical-report-draft.pdf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        rightMargin=19 * mm,
        leftMargin=19 * mm,
        topMargin=19 * mm,
        bottomMargin=23 * mm,
        title="AntiCNSpy - Laporan Teknis (Draf)",
        author="Kelompok IF4020",
    )
    document.build(story, onFirstPage=decorate, onLaterPages=decorate)
    (ROOT / "docs/report.md").write_text(
        "\n".join(markdown).rstrip() + "\n", encoding="utf-8", newline="\n"
    )
    print(destination)


if __name__ == "__main__":
    main()
