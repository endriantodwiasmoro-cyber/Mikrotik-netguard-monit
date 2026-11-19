# Panduan Cloudflare Tunnel Setup
Dokumen ini memandu Anda dalam menyiapkan Cloudflare Tunnel untuk akses dashboard NetGuardMonit secara aman melalui HTTPS, tanpa membuka port di router atau firewall Windows.

## ☁️ Persyaratan
1.  Akun Cloudflare dan domain yang terkelola di Cloudflare.
2.  Cloudflare Zero Trust Zero Trust teraktifkan.
3.  Aplikasi Cloudflare Access (Self-hosted) dikonfigurasi untuk domain monitor.
4.  Token Tunnel (`CLOUDFLARE_TUNNEL_TOKEN`) disalin ke file `.env`.

## 🚀 Langkah Setup Tunnel
1.  **Buat Tunnel:** Di **Cloudflare Zero Trust → Networks → Tunnels**, buat *tunnel* yang dikelola dari jauh.
2.  **Tambahkan Hostname:** Tambahkan *hostname* publik (contoh: `monitor.example.com`) dengan *service* `http://app:8000` (sesuai konfigurasi Docker Compose).
3.  **Konfigurasi Access:** Buat aplikasi Cloudflare Access untuk *hostname* tersebut. **Wajibkan** penyedia identitas yang Anda inginkan dan aktifkan MFA.
4.  **Dapatkan Token:** Salin *token tunnel* yang dihasilkan dan masukkan ke `CLOUDFLARE_TUNNEL_TOKEN` di `.env`.

**Keunggulan:**
Cloudflare Tunnel membuat koneksi **keluar** (outbound) yang terautentikasi dari host Docker Anda. Ini **tidak memerlukan** *port forwarding* pada router MikroTik atau firewall Windows, memastikan keamanan LAN-only tetap terjaga.

## 🔑 Keamanan Akses
Pastikan **Cloudflare Access** digunakan sebagai lapisan keamanan kedua setelah *password* admin wajib di NetGuardMonit.
