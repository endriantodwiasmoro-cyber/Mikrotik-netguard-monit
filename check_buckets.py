import sqlite3
from datetime import datetime, timedelta, timezone

db = sqlite3.connect('/data/netguard.db')
db.row_factory = sqlite3.Row

now = datetime.now(timezone.utc)
since = (now - timedelta(hours=1)).isoformat(timespec='seconds')
print('since (UTC):', since)

rows = db.execute("""
    SELECT
        observed_at,
        datetime(observed_at, '+420 minutes') as local_dt,
        strftime('%Y-%m-%d %H:%M:%S', datetime(observed_at, '+420 minutes')) as bucket
    FROM interface_samples
    WHERE interface_name = 'bridge-DHCP' AND observed_at >= ?
    ORDER BY observed_at ASC
    LIMIT 10
""", (since,)).fetchall()

for r in rows:
    print(dict(r))
