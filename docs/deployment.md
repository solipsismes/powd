# Deploying powd

powd slots between nginx and your application:

```
Internet → nginx (TLS) → powd :8081 → application :8080
```

nginx keeps doing what it does well — TLS, HTTP/2, compression, static
files, rate limiting. powd only decides whether a request has paid for
admission.

## nginx

Proxy the locations you want protected through powd instead of the
application. The simplest arrangement sends everything through powd and
lets powd's own `protect`/`exclude` lists decide:

```nginx
server {
    listen 443 ssl;
    server_name example.org;

    # ... TLS configuration ...

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Two headers matter to powd:

- `Host` — passed through to the application unchanged.
- `X-Real-IP` — powd's source of the client address. Required if you
  enable `bind_ip`; without it powd sees only nginx's address.

If the application uses WebSockets, add the standard upgrade headers so
they survive both hops (powd's reverse proxy passes upgrades through):

```nginx
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
```

Alternatively, protect only some locations by routing just those through
powd (`location /forum/ { proxy_pass http://127.0.0.1:8081; ... }`) and
sending the rest straight to the application. Prefer powd's own
`protect`/`exclude` lists unless you have a reason not to: one place to
look, and the `/.powd/verify` endpoint is guaranteed to be reachable.

powd's config for the setup above:

```toml
listen      = "127.0.0.1:8081"
upstream    = "http://127.0.0.1:8080"
secret_file = "/var/lib/powd/secret"

protect = ["/"]
exclude = ["/rss", "/robots.txt", "/favicon.ico", "/healthz"]
```

## systemd

`/etc/systemd/system/powd.service`:

```ini
[Unit]
Description=powd proof-of-work gateway
Documentation=https://github.com/you/powd
After=network.target

[Service]
ExecStart=/usr/local/bin/powd -c /etc/powd.toml
Restart=on-failure

# Sandboxing. DynamicUser gives powd a transient unprivileged user;
# StateDirectory creates /var/lib/powd owned by it, which is where
# secret_file should point.
DynamicUser=yes
StateDirectory=powd
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

```sh
install -m 755 powd /usr/local/bin/powd
install -m 644 powd.toml.example /etc/powd.toml   # then edit
systemctl enable --now powd
journalctl -u powd                                 # logs
```

powd validates its config with `powd -t -c /etc/powd.toml`; run it
before restarting after any edit.

## Checklist

- [ ] `powd -t` passes on the production config.
- [ ] `secret_file` set (or accept that every restart re-challenges
      everyone).
- [ ] Feeds, `robots.txt`, health checks, and anything machines must
      reach are in `exclude`.
- [ ] nginx sends `X-Real-IP` (mandatory if `bind_ip = true`).
- [ ] TLS in front: without HTTPS, browsers refuse WebCrypto and the
      challenge page will say so instead of solving.
