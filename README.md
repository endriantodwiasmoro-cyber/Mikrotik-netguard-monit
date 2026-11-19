# NetGuard Monit

Monitoring LAN seperti PRTG untuk MikroTik hAP ac (RouterOS 7.25.1) dengan dashboard browser dan notifikasi Telegram. Tidak pernah mengekspos RouterOS ke internet: pengambil data memanggil REST RouterOS private HTTPS dari server, sementara dashboard diakses melalui Cloudflare Tunnel over HTTPS.

## Fitur (ala PRTG)

- **Trafik antarmuka realtime** — RX/TX bits per detik per antarmuka, dengan granularitas detik, menit, jam, hari, dan bulan
- **Status link UP/DOWN** — deteksi router tidak terhubung dan antarmuka WAN mati, dengan alert otomatis dan pesan pemulihan (recovery)
- **Alert DDoS** — lalu lintas tinggi melebihi ambang batas (default 100 Mbps) pada antarmuka WAN
- **Alert Broadcast / storm** — jumlah packet drop tinggi yang mengindikasikan kemungkinan siaran berlebih
- **Kesehatan sistem RouterOS** — beban CPU, ruang disk, versi, board, uptime
- **Notifikasi Telegram** — alert saat masalah naik, pengingat selama cooldown, dan pemulihan saat kondisi membaik
- **Dashboard aman** — kata sandi admin wajib, verifikasi Argon2id, sesi sisi server, CSRF, secure HttpOnly cookie, rate limiting login, header keamanan ketat

## Model keamanan

- RouterOS REST hanya tersedia di LAN dari host Docker. Jangan port-forward Winbox, API, API-SSL, SSH, WebFig, atau REST.
- Aplikasi tidak memiliki port Docker yang dipublikasikan. Cloudflare Tunnel adalah satu-satunya ingress.
- Dashboard dilindungi kata sandi administrator yang wajib, Argon2id, sesi opaque sisi server, CSRF, secure HttpOnly cookie, rate limiting, header keamanan ketat, dan Cloudflare Access disarankan sebagai lapisan kedua.
- Kredensial router, kata sandi admin, token Telegram, dan token tunnel disimpan hanya di `.env` pada drive `R:` dan dikecualikan dari version control.
- Data SQLite persisten ada di `R:\NetGuardMonit\data\netguard.db`. Volume compose relatif terhadap proyek, jadi juga tetap di `R:`.

## Prasyarat

1. Docker Desktop untuk Windows terinstal dan berjalan dalam mode container Linux.
2. Host ini dapat mencapai alamat LAN router melalui HTTPS.
3. Akun Cloudflare, domain di Cloudflare, dan (direkomendasikan) aplikasi Cloudflare Access.
4. Bot Telegram dan chat ID target jika notifikasi diinginkan.

## Persiapan RouterOS

Buat akun khusus dengan hak terbatas dan izinkan koneksi REST-nya hanya dari host Windows/LAN. Jangan menggunakan akun administrator. Uji akun hanya terhadap endpoint berikut, lalu hapus kebijakan yang tidak diperlukan:

- `GET /rest/system/resource`
- `GET /rest/interface`
- `GET /rest/system/health` (opsional; hardware yang tidak didukung dengan aman tidak mengembalikan bacaannya)

Aktifkan HTTPS dengan sertifikat tepercaya jika memungkinkan. Sertifikat server self-signed harus diganti dengan sertifikat CA pribadi; salin hanya sertifikat CA ke `data\certs\router-ca.pem` dan atur `MIKROTIK_TLS_VERIFY=/data/certs/router-ca.pem`. Jangan mengatur verifikasi TLS menjadi `false` dalam produksi.

Bantai rantai input router sebelum mengaktifkan REST. Contoh niat kebijakan: izinkan TCP/443 ke router hanya dari IP LAN host ini, lalu buang port manajemen dari setiap sumber lain. Adapt dan tinjau aturan firewall sebelum menerapkannya—jangan tempel aturan luas yang menghadap internet.

## Pengaturan Cloudflare

1. Di **Cloudflare Zero Trust → Networks → Tunnels**, buat tunnel yang dikelola dari jauh.
2. Tambahkan hostname publik (misalnya `monitor.example.com`) dengan service `http://app:8000`.
3. Buat aplikasi Cloudflare Access self-hosted untuk hostname tersebut. Wajibkan penyedia identitas dan aktifkan MFA sesuai kebutuhan.
4. Salin token tunnel ke `CLOUDFLARE_TUNNEL_TOKEN`.

Cloudflare Tunnel membuat koneksi keluar yang terautentikasi. Tidak memerlukan port router atau firewall Windows yang diarahkan ke dalam.

## Instal dan mulai

Dari PowerShell, di `R:\NetGuardMonit`:

```powershell
Copy-Item .env.example .env
notepad .env
# Isi setiap nilai yang diperlukan, terutama APP_ADMIN_PASSWORD dan APP_TRUSTED_HOSTS.
docker compose up -d --build
```

Kunjungi hostname Cloudflare, lewati Cloudflare Access jika dikonfigurasi, lalu masuk dengan `APP_ADMIN_PASSWORD`.

Operasi berguna:

```powershell
docker compose ps
docker compose logs -f app
docker compose logs -f cloudflared
docker compose down
```

## Telegram

Atur keduanya `TELEGRAM_BOT_TOKEN` dan `TELEGRAM_CHAT_ID` untuk mengaktifkan notifikasi. Monitor mengirim pesan ketika router, antarmuka WAN yang dikonfigurasi, atau ambang CPU masuk status alert, mengulangi alert yang berlangsung hanya setelah cooldown yang dikonfigurasi, dan mengirim pesan pemulihan setelah kondisi membaik.

## Cadangan dan pembaruan

Hentikan tumpukan sebelum menyalin `data\netguard.db` untuk cadangan sederhana yang konsisten. Simpan `.env` terpisah dan lindungi. Sebelum pembaruan, cadangkan `data`, tinjau kunci dependensi dan tag image container dengan sengaja, lalu rebuild dengan `docker compose up -d --build`.

## Koleksi data

Secara default aplikasi menggunakan **RouterOS REST** untuk sistem dan statistik antarmuka (`MIKROTIK_COLLECT_METHOD=rest`). Jika REST tidak tersedia, gunakan **SNMPv2c** dengan mengatur `MIKROTIK_COLLECT_METHOD=snmp` atau `both`, dan isi `MIKROTIK_SNMP_HOST` serta `MIKROTIK_SNMP_COMMUNITY`.

Data trafik disimpan sebagai sampel time-series di SQLite. Granularitas tersedia melalui API:
- `GET /api/interfaces/{nama}/traffic?granularity=second|minute|hour|day|month&range_hours=N`

Sampel mentah dipertahankan 7 hari; agregasi ditampilkan melalui endpoint API.

## Batasan

MVP ini mencatat kemungkinan router, beban CPU, ruang disk, dan status antarmuka WAN yang dikonfigurasi. Tidak memeriksa klien individual, isi paket, atau log firewall. Ketersediaan dashboard tidak membuktikan WAN sehat; itu membuktikan host monitor dapat mencapai Cloudflare dan router sesuai dengan keadaan yang dikumpulkan.
