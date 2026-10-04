# Target Reachability Diagnostics

Generated: 2026-10-04T11:30:47.611237+00:00

One plain GET request per target, to tell a real block apart from "no fingerprint signal".

### example.com — ✅ reachable, no block signature
- HTTP status: 200
- Server header: `cloudflare`
- Response size: 577 bytes
- HTTP 200, no block signature — responded normally, 577 bytes, Server: 'cloudflare' (if httpx still finds 0 technologies, the site just isn't leaking a fingerprint, not blocking)

### okx.com — ✅ reachable, no block signature
- HTTP status: 200
- Server header: `cloudflare`
- Response size: 19999 bytes
- HTTP 200, no block signature — responded normally, 19999 bytes, Server: 'cloudflare' (if httpx still finds 0 technologies, the site just isn't leaking a fingerprint, not blocking)

### Superdrug.com — 🚫 likely blocked
- HTTP status: 403
- Server header: `AkamaiGHost`
- Response size: 363 bytes
- HTTP 403, looks like active blocking (status 403, body mentions 'access denied') — Server: 'AkamaiGHost'

