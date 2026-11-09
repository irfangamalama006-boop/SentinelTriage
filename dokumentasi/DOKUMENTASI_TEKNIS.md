# DOKUMENTASI TEKNIS SENTINELTRIAGE

## Digital Forensics & Malware Triage

**Penyusun:** Irfan Maulana  
**Proyek:** SentinelTriage  
**Platform pengembangan:** macOS  
**Antarmuka:** Streamlit  
**Bahasa pemrograman:** Python

---

## 1. Pendahuluan

SentinelTriage merupakan prototipe alat bantu pemeriksaan awal
digital forensics dan malware triage. Aplikasi ini membantu analis
memeriksa file, mencocokkan indikator menggunakan aturan YARA,
mengumpulkan artefak sistem yang didukung, dan menghasilkan laporan.

Aplikasi ditujukan untuk pemeriksaan awal pada perangkat dan data
yang pengguna berwenang untuk periksa.

## 2. Tujuan

1. Memeriksa file dan menghitung hash SHA-256.
2. Mendeteksi kecocokan pola berdasarkan aturan YARA.
3. Mendukung pengumpulan artefak sistem sesuai kemampuan aplikasi.
4. Menghasilkan laporan HTML, PDF, dan JSON.
5. Menyediakan antarmuka untuk menjalankan pemeriksaan dan membaca
   hasilnya.

## 3. Teknologi

- Python sebagai bahasa pemrograman utama.
- Streamlit sebagai antarmuka dashboard.
- FastAPI sebagai backend API untuk autentikasi, manajemen kasus, pemindaian, dan temuan.
- MySQL sebagai basis data backend.
- yara-python untuk pemindaian berbasis aturan YARA.
- psutil untuk pengumpulan informasi proses dan jaringan.
- ReportLab untuk pembuatan laporan PDF.
- cryptography untuk dukungan enkripsi laporan.

Versi dependensi mengikuti lingkungan virtual dan konfigurasi
proyek yang digunakan selama pengembangan dan pengujian.

## 4. Arsitektur dan Modul

SentinelTriage menggunakan dashboard Streamlit sebagai antarmuka
pengguna dan CLI sebagai jalur pemeriksaan melalui terminal.
Backend FastAPI disediakan sebagai layanan terpisah yang terhubung
dengan basis data MySQL.

Modul utama:

- app.py: dashboard dengan enam menu utama.
- sentineltriage/cli.py: pemeriksaan melalui command line.
- sentineltriage/collector.py: pengumpulan artefak host, proses,
  jaringan, dan artefak sistem yang didukung.
- sentineltriage/file_triage.py: pemeriksaan awal file, termasuk
  hash SHA-256 dan identifikasi tipe file.
- sentineltriage/yara_scan.py: pemindaian berdasarkan aturan YARA.
- sentineltriage/process_analysis.py: penilaian awal metadata proses
  menggunakan aturan heuristik.
- sentineltriage/network_analysis.py: penilaian awal koneksi jaringan,
  klasifikasi alamat, dan pengelompokan data duplikat.
- sentineltriage/timeline.py: penyusunan urutan peristiwa.
- sentineltriage/html_report.py: pembuatan laporan HTML.
- sentineltriage/reporting.py: pembuatan laporan JSON dan PDF,
  termasuk dukungan enkripsi JSON.
- backend/app/: layanan FastAPI untuk autentikasi, manajemen kasus,
  pemindaian, dan pengelolaan temuan.

Dashboard Streamlit dan backend FastAPI merupakan layanan terpisah.
Penilaian proses dan jaringan bersifat awal dan memerlukan verifikasi
analis. Status perlu ditinjau tidak otomatis berarti ancaman.

## 5. Instalasi dan Menjalankan Aplikasi

Masuk ke direktori proyek:

    cd ~/Downloads/SentinelTriage

Jalankan dashboard:

    ./.venv-macos/bin/python -m streamlit run app.py

Jalankan tes otomatis:

    ./.venv-macos/bin/python -m pytest -q

Gunakan lingkungan virtual proyek agar dependensi yang digunakan
konsisten dengan instalasi pengembangan.

## 6. Pengujian Otomatis

Hasil pengujian otomatis terbaru:

    33 passed

Seluruh 33 tes yang dijalankan berhasil pada pengujian tersebut.
Pengujian mencakup fungsi pemindaian, pelaporan, timeline,
serta analisis proses dan jaringan.

Hasil ini menunjukkan bahwa tes otomatis yang tersedia lulus,
tetapi tidak dengan sendirinya membuktikan seluruh skenario
penggunaan atau keamanan aplikasi sudah diuji.

## 7. Pengujian YARA dengan Data Sintetis

ID kasus: yara-synthetic-test-03

Target:
test-data/sampel-aman/indikator-simulasi.txt

Aturan:
test-data/aturan/aturan-uji.yar

Nama aturan:
SentinelTriage_Synthetic_Test

Indikator:
SIMULATED_TRIAGE_MARKER_12345

Hasil:
- File dipindai: 1
- Error YARA: 0
- Aturan cocok: SentinelTriage_Synthetic_Test
- String $marker ditemukan satu kali.

Kesimpulan:
Pengujian YARA pada sampel sintetis berhasil. Hasil ini memvalidasi
pencocokan marker uji, bukan kemampuan mendeteksi seluruh jenis malware.

## 8. Pemeriksaan Integritas File

Pada kasus gui-yara-test-02, nilai SHA-256 aktual file SVG cocok
dengan nilai SHA-256 yang tercatat dalam laporan.

Kecocokan tersebut mendukung pemeriksaan integritas terhadap catatan
hash. Hash saja tidak membuktikan asal-usul atau keaslian file.

## 9. Laporan dan Bukti Pengujian

Bukti pengujian disimpan di:

    dokumentasi/bukti-pengujian/

File yang tersedia:
- report.html
- report.json
- report.pdf

Bukti tersebut berasal dari kasus yara-synthetic-test-03.

## 10. Navigasi Dashboard

Menu utama dashboard:

1. Dashboard
2. Workspace Investigasi
3. File Scanner
4. YARA Scanner
5. Live Triage
6. Report Center

Dashboard menampilkan ringkasan aplikasi. Workspace Investigasi
digunakan untuk pengelolaan kasus dan pemindaian melalui backend.
File Scanner dan YARA Scanner mendukung pemeriksaan file.
Live Triage mengumpulkan artefak sistem yang didukung.
Report Center digunakan untuk melihat laporan yang tersedia
dalam format HTML, PDF, dan JSON.

## 11. Batasan dan Keamanan

- YARA match bukan bukti tunggal bahwa file adalah malware.
- Tidak adanya temuan bukan jaminan perangkat bersih.
- Pengumpulan artefak langsung dapat dibatasi izin sistem.
- Live collection dapat mengubah kondisi sistem dan kehilangan
  sebagian bukti yang bersifat volatil.
- Pemeriksaan hanya boleh dilakukan pada perangkat dan data yang
  pengguna berwenang untuk periksa.
- Hasil harus ditinjau berdasarkan konteks dan bukti tambahan.

## 12. Kesimpulan

Pengembangan SentinelTriage telah mencakup pemeriksaan file,
pemindaian YARA, pengumpulan artefak sistem, penilaian awal proses
dan jaringan, penyusunan timeline, serta pembuatan laporan.

Pada pengujian otomatis terbaru, 33 tes berhasil dijalankan.
Pengujian YARA menggunakan sampel sintetis juga berhasil
mencocokkan marker uji, dan pemeriksaan integritas file
menunjukkan kecocokan nilai SHA-256 dengan catatan laporan.

SentinelTriage merupakan prototipe alat bantu pemeriksaan awal
untuk kebutuhan defensif. Hasil analisis otomatis tetap harus
diverifikasi oleh analis. Validasi tambahan diperlukan sebelum
digunakan dalam investigasi nyata atau lingkungan produksi.

---

Dokumentasi ini mencatat hasil pengujian yang benar-benar telah
diperoleh selama pengembangan.
