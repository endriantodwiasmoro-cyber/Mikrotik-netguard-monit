# Konfigurasi RouterOS untuk NetGuardMonit

Dokumen ini berisi panduan langkah demi langkah untuk menyiapkan MikroTik RouterOS (v7.25.1) agar dapat diakses secara aman oleh NetGuardMonit. **Penting:** Seluruh akses harus **LAN-only**. Jangan pernah melakukan port-forwarding ke Winbox, API, SSH, atau WebFig dari internet.

## 🔒 Langkah Keamanan
1.  **Buat Akun Khusus:** Buat akun pengguna khusus (`netguard-readonly`) dengan hak terbatas (hanya `read-only` API access) dan **JANGAN** gunakan akun administrator.
2.  **Izinkan REST:** Batasi kebijakan firewall agar koneksi TCP/443 hanya diizinkan dari **IP LAN host Windows** tempat Docker berjalan. **Buang** semua kebijakan yang mengizinkan akses dari sumber lain (terutama dari WAN/Internet).
3.  **Aktifkan HTTPS:** Pastikan REST API menggunakan HTTPS. Gunakan sertifikat tepercaya atau CA pribadi. Jika menggunakan CA pribadi, salin sertifikat CA ke `data/certs/router-ca.pem` dan atur `MIKROTIK_TLS_VERIFY=/data/certs/router-ca.pem` di `.env`. Jangan pernah mengatur verifikasi TLS menjadi `false` dalam produksi.

## 📡 Endpoint yang Diperlukan
Hanya endpoint berikut yang diperlukan untuk monitoring:
- `GET /rest/system/resource` (Informasi sistem)
- `GET /rest/interface` (Status antarmuka dan trafik)
- `GET /rest/system/health` (Kesehatan perangkat)

**CATATAN:** Uji akun baru Anda hanya pada endpoint di atas sebelum diterapkan secara permanen.

## 🛠️ Persyaratan Lingkungan
- RouterOS v7.25.1 atau lebih baru.
- Akses HTTPS LAN dari host Windows.