# AntiCNSpy - laporan teknis (DRAF)

Identitas, foto anggota, dan pembagian tugas akan diberikan kemudian.
Bantuan AI digunakan sesuai izin yang dikonfirmasi pengguna.

## 1. Pendahuluan

AntiCNSpy merupakan kakas CLI untuk penandatanganan dan verifikasi rilis perangkat lunak. Rancangan mengadaptasi alur penandatanganan blob pada Sigstore Cosign: artefak di-hash, informasinya dibentuk sebagai manifest, kemudian manifest ditandatangani. Implementasi alur aplikasi, format, validasi, serta trust store dilakukan dalam program sendiri. Cosign tidak digunakan sebagai pengganti implementasi. Kepercayaan dikelola secara lokal dan eksplisit, tanpa sertifikat atau transparency log.

## 2. Dasar teori

Tanda tangan digital memungkinkan pemeriksaan integritas pesan dan kepemilikan kunci privat yang sesuai dengan kunci publik. Hash SHA-256 artefak mengikat isi berkas, sedangkan tanda tangan atas seluruh manifest mengikat paket, versi, profil, keyid, nama berkas, ukuran, dan hash. RSA-PSS menggunakan padding probabilistik; ECDSA menggunakan operasi kurva P-256 dengan nonce aman; Ed25519 menggunakan PureEdDSA secara deterministik. Keabsahan matematis tanda tangan tidak dengan sendirinya memberi kepercayaan kepada penerbit atau menjamin perangkat lunak bebas malware.

## 3. Perancangan sistem

Program memisahkan CLI, format, artefak, kunci, operasi kriptografi, trust store, penandatanganan, dan verifikasi. Manifest dibentuk dalam urutan field tetap dan UTF-8 tanpa BOM/spasi/baris baru. Bundle menyimpan byte manifest serta tanda tangan dalam Base64 standar. Parser mendeteksi field duplikat saat parsing, menolak field tambahan dan tipe yang salah, lalu membandingkan serialisasi canonical dengan byte asli. Tanda tangan selalu diperiksa terhadap byte asli yang tersimpan.

| Urutan | Kegagalan | Exit |
| --- | --- | --- |
| 1 | INPUT_ERROR | 2 |
| 2 | FORMAT_ERROR | 1 |
| 3 | UNSUPPORTED_ALGORITHM | 1 |
| 4 | KEY_NOT_TRUSTED | 1 |
| 5 | INVALID_SIGNATURE | 1 |
| 6 | METADATA_MISMATCH | 1 |
| 7 | ARTIFACT_MISMATCH | 1 |
| 8 | OK | 0 |

## 4. Implementasi dan simulasi

Implementasi menggunakan Python dan cryptography 50.0.2. CLI menggunakan argparse; JSON, Base64, hashing, dan penulisan atomik menggunakan pustaka standar. Kunci privat berformat PKCS8 PEM dan kunci publik SPKI PEM. Fingerprint dihitung dari SHA-256 DER SPKI hasil ekspor ulang. Profil RSA menggunakan modulus 3072 bit, eksponen 65537, SHA-256/MGF1-SHA-256 dan salt tepat 32 byte. ECDSA menggunakan P-256/SHA-256 dan mengubah keluaran DER menjadi r || s, masing-masing 32 byte big-endian. Ed25519 menerima byte manifest secara langsung tanpa prehash eksternal.

## 5. Pengujian fungsional dan interoperabilitas

Snapshot pengujian mencatat 128 pengujian pytest dengan 0 kegagalan/error serta 29 skenario bukti U01-U14 yang seluruhnya lulus. U01 menguji teks, biner dan berkas kosong pada ketiga profil. U14 menandatangani manifest identik dua kali: RSA-PSS dan ECDSA menghasilkan tanda tangan berbeda; Ed25519 menghasilkan tanda tangan identik; keduanya tetap lolos verifikasi. OpenSSL CLI digunakan sebagai kakas eksternal untuk menguji kedua arah interoperabilitas pada semua profil, dengan konversi DER/raw pada ECDSA. Bukti ini tidak menyatakan independensi backend kriptografi, karena pustaka Python juga menggunakan OpenSSL.

| Skenario | Hasil aktual | Lulus |
| --- | --- | --- |
| U01-rsa-pss-sha256-text | OK | True |
| U01-rsa-pss-sha256-binary | OK | True |
| U01-rsa-pss-sha256-empty | OK | True |
| U01-ecdsa-p256-sha256-text | OK | True |
| U01-ecdsa-p256-sha256-binary | OK | True |
| U01-ecdsa-p256-sha256-empty | OK | True |
| U01-ed25519-text | OK | True |
| U01-ed25519-binary | OK | True |
| U01-ed25519-empty | OK | True |
| U02 | ARTIFACT_MISMATCH | True |
| U03-insert | ARTIFACT_MISMATCH | True |
| U03-delete | ARTIFACT_MISMATCH | True |
| U04 | INVALID_SIGNATURE | True |
| U05 | INVALID_SIGNATURE | True |
| U06-empty | KEY_NOT_TRUSTED | True |
| U06-remove | KEY_NOT_TRUSTED | True |
| U07 | KEY_NOT_TRUSTED | True |
| U08 | METADATA_MISMATCH | True |
| U09 | METADATA_MISMATCH | True |
| U10-duplicate | FORMAT_ERROR | True |
| U10-type | FORMAT_ERROR | True |
| U10-base64 | FORMAT_ERROR | True |
| U10-oversize | FORMAT_ERROR | True |
| U11 | UNSUPPORTED_ALGORITHM | True |
| U12 | KEY_NOT_TRUSTED | True |
| U13 | OK | True |
| U14-rsa-pss-sha256-first | OK | True |
| U14-ecdsa-p256-sha256-first | OK | True |
| U14-ed25519-first | OK | True |

## 6. Distribusi dan integrasi CI/CD

Image Linux/amd64 telah dibangun dan diuji secara lokal. Image mengemas seluruh dependensi, menggunakan entrypoint CLI, dan mendukung jaringan dinonaktifkan, bind mount serta identitas nonroot. Kunci privat CI terpisah dari fixture publik, diberikan melalui secret, di-mount read-only hanya saat sign, dan dibersihkan. Verifikasi menggunakan trust store publik yang disiapkan independen. Harness menyimpan exit code asli, hasil JSON dan keberadaan marker deployment. Publikasi image publik dan workflow hosted belum dijalankan; hasil lokal secara eksplisit ditandai registry_pull=false dan tidak menggantikan bukti registry-pull.

| Skenario | Profil / kondisi | Hasil lokal |
| --- | --- | --- |
| C01 | rsa-pss-sha256 | OK / True |
| C01 | ecdsa-p256-sha256 | OK / True |
| C01 | ed25519 | OK / True |
| C02 | ed25519 | ARTIFACT_MISMATCH / True |
| C03 | ed25519 | KEY_NOT_TRUSTED / True |
| C04 | ed25519 | INPUT_ERROR / True |
| C05 | offline/nonroot/no TTY | OK / True |

## 7. Analisis keamanan

Modifikasi artefak ditolak melalui ukuran/hash; modifikasi manifest/tanda tangan ditolak sebelum metadata diperiksa. Kepercayaan memerlukan kecocokan keyid, profil dan izin paket yang diharapkan pengguna. Semua entri trust store divalidasi. Kunci privat tidak dimasukkan ke bundle, image atau log. Berkas privat Unix memakai mode 0600; penimpaan memerlukan opsi eksplisit. Nonce ECDSA dan salt RSA menggunakan CSPRNG backend. Pembaruan trust store memakai temporary file yang di-flush/fsync dan diganti secara atomik. Penulisan bersamaan tetap memerlukan locking eksternal. Penghapusan kunci berlaku berdasarkan trust store saat verifikasi. Pencegahan rollback otomatis memerlukan trusted state tambahan; versi harapan dari caller hanya menolak rilis yang berbeda dari versi tersebut.

## 8. Pengukuran performa

Artefak deterministik berukuran 1 KiB, 1 MiB dan 16 MiB digunakan sama pada seluruh profil. Pembangkitan kunci diukur 5 kali per algoritma. Setiap metrik sign/verify/hash menggunakan 5 warm-up dan 30 pengulangan terukur dengan perf_counter_ns. Median dan P95 nearest-rank dihitung dari sampel mentah; P95 adalah elemen ceil(0.95*n) pada urutan naik dengan indeks mulai 1. Hash artefak di memori diukur terpisah. Operasi crypto atas manifest mencakup hash internal algoritma, tanpa I/O/hash artefak. Pengukuran CLI mencakup proses Python baru, parsing, I/O, hash dan keluaran. Hasil adalah snapshot lingkungan lokal; proses latar belakang dapat menimbulkan noise dan angka tidak mewakili seluruh perangkat atau pipeline.

Lingkungan: Windows-11-10.0.26200-SP0; AMD64 Family 25 Model 116 Stepping 1, AuthenticAMD; 12 logical CPU; Python 3.13.3; cryptography 50.0.2; backend OpenSSL 4.0.3 29 Sep 2026

| Profil | Keygen median (ms) | Publik DER | Privat DER | Signature |
| --- | --- | --- | --- | --- |
| rsa-pss-sha256 | 130.71360 | 422 | 1793 | 384 |
| ecdsa-p256-sha256 | 0.02040 | 91 | 138 | 64 |
| ed25519 | 0.06860 | 44 | 48 | 64 |

Operasi kriptografi atas manifest (seluruh waktu dalam milidetik):

| Profil / byte artefak | Sign median | Sign P95 | Verify median | Verify P95 |
| --- | --- | --- | --- | --- |
| rsa-pss-sha256 / 1024 | 0.59385 | 0.73180 | 0.03880 | 0.05970 |
| rsa-pss-sha256 / 1048576 | 0.61090 | 1.07680 | 0.05735 | 0.06590 |
| rsa-pss-sha256 / 16777216 | 0.59555 | 1.04790 | 0.04040 | 0.07660 |
| ecdsa-p256-sha256 / 1024 | 0.02005 | 0.02070 | 0.05045 | 0.06600 |
| ecdsa-p256-sha256 / 1048576 | 0.03825 | 0.08050 | 0.09570 | 0.10480 |
| ecdsa-p256-sha256 / 16777216 | 0.02965 | 0.06280 | 0.08480 | 0.27050 |
| ed25519 / 1024 | 0.04590 | 0.21000 | 0.11740 | 0.20310 |
| ed25519 / 1048576 | 0.06110 | 0.06780 | 0.15660 | 0.17140 |
| ed25519 / 16777216 | 0.04970 | 0.10590 | 0.11340 | 0.25320 |

Pengukuran aplikasi lengkap (milidetik, termasuk startup/I/O/hash):

| Profil / byte artefak | Sign median | Sign P95 | Verify median | Verify P95 |
| --- | --- | --- | --- | --- |
| rsa-pss-sha256 / 1024 | 271.97395 | 338.27550 | 160.59920 | 246.72330 |
| rsa-pss-sha256 / 1048576 | 251.50900 | 366.79840 | 155.95555 | 216.52300 |
| rsa-pss-sha256 / 16777216 | 265.57920 | 301.01370 | 163.16455 | 200.68430 |
| ecdsa-p256-sha256 / 1024 | 174.55825 | 196.38370 | 233.73640 | 387.69420 |
| ecdsa-p256-sha256 / 1048576 | 194.56195 | 315.17510 | 236.86865 | 292.32570 |
| ecdsa-p256-sha256 / 16777216 | 276.34190 | 343.31340 | 247.93630 | 319.59620 |
| ed25519 / 1024 | 241.23385 | 313.36050 | 186.45145 | 251.14730 |
| ed25519 / 1048576 | 191.30810 | 284.74720 | 147.88865 | 264.94650 |
| ed25519 / 16777216 | 199.79235 | 320.96920 | 196.04125 | 338.21620 |

Ukuran bundle/manifest dan hash artefak lengkap tersedia dalam test_cases/benchmarks/summary.json; seluruh sampel dalam raw.csv. Waktu crypto tidak bertambah sebanding ukuran artefak karena pesan yang ditandatangani adalah manifest yang kecil. Waktu aplikasi juga mencakup pembacaan dan hashing artefak; jangan menyimpulkan performa crypto dari waktu CLI saja.

## 9. Kesimpulan dan pengembangan

Fungsi wajib lokal telah diimplementasikan dan bukti pengujian menunjukkan penolakan yang sesuai untuk skenario manipulasi, kesalahan format dan kepercayaan. Pemisahan manifest, bundle dan trust store menjaga batas antara integritas data dan otorisasi penerbit. Langkah penyelesaian eksternal adalah publikasi image/tag, pencatatan digest yang sebenarnya, penyiapan secret GitHub, dan pengambilan bukti workflow registry consumer. Identitas/foto anggota serta pembagian tugas menunggu data pengguna. Pengembangan berikutnya dapat mencakup penyimpanan kunci terenkripsi, freshness policy, locking trust store dan layanan timestamp.

## 10. Referensi dan lampiran

Spesifikasi Tugas3-nOinject.pdf, bagian 2.1-2.9 dan 3.1.

RFC 8017 (RSA-PSS); RFC 6979 (ECDSA nonce deterministik); RFC 8032 (Ed25519).

RFC 8410 (SPKI Ed25519); RFC 4648 (Base64); RFC 5958 (kunci asimetris).

Dokumentasi cryptography: https://cryptography.io/en/stable/

Dokumentasi Python JSON: https://docs.python.org/3/library/json.html

Source: https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi

Reproduksi: python -m pytest; python scripts/run_evidence.py; python benchmarks/run.py.

Bukti: test_cases/results, fixtures, benchmarks dan container-local. Perintah aktual serta hasil yang diharapkan dicatat dalam setiap case.json.

Tautan workflow hosted, digest publik, foto/identitas dan tabel pembagian tugas: menyusul.
