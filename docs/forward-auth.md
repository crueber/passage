# Forward-Auth Integration

Passage supports the **forward-auth pattern** for reverse proxies. When enabled, the reverse proxy intercepts every incoming request and asks Passage whether the user is authenticated before forwarding it to the upstream service. This is a good fit when an application has no built-in authentication and you want to gate it behind Passage without modifying the app.

```
Browser → Nginx/Traefik → Passage /auth/nginx ──→ 200 OK + identity headers
                        ↑                                    ↓
                        └── protected app ←── upstream service
```

On `401`, the reverse proxy redirects the browser to Passage's login page. After a successful login, Passage sets a session cookie and bounces the user back to their original destination.

> **Recommendation**: For applications that support OAuth 2.0 or OIDC natively, use Passage as an [OAuth 2.0 / OIDC provider](../README.md#oauth-20--oidc-provider) instead. Forward-auth is best suited for legacy apps or simple services with no auth support.

---

## Identity headers

On a successful auth check, Passage sets the following response headers so your reverse proxy can forward them to the upstream application:

| Header | Content |
|---|---|
| `X-Passage-Username` | The authenticated user's username |
| `X-Passage-Email` | The authenticated user's email address |
| `X-Passage-Name` | The authenticated user's display name |
| `X-Passage-User-ID` | The authenticated user's UUID |
| `X-Passage-Is-Admin` | `"true"` if the user is an admin, `"false"` otherwise |

---

## Nginx

Passage exposes `/auth/nginx` for use with Nginx's `auth_request` module.

```nginx
# In your server {} block for the protected application
location /auth/ {
    internal;
    proxy_pass              http://localhost:8080;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
    proxy_set_header        X-Original-URL $scheme://$http_host$request_uri;
}

location / {
    auth_request /auth/nginx;
    error_page 401 403 = @login;

    # Forward identity headers to your upstream
    auth_request_set $passage_user  $upstream_http_x_passage_username;
    auth_request_set $passage_email $upstream_http_x_passage_email;
    auth_request_set $passage_name  $upstream_http_x_passage_name;
    auth_request_set $passage_uid   $upstream_http_x_passage_user_id;
    auth_request_set $passage_admin $upstream_http_x_passage_is_admin;

    proxy_set_header X-Passage-Username $passage_user;
    proxy_set_header X-Passage-Email    $passage_email;
    proxy_set_header X-Passage-Name     $passage_name;
    proxy_set_header X-Passage-User-ID  $passage_uid;
    proxy_set_header X-Passage-Is-Admin $passage_admin;

    proxy_pass http://your-upstream-service;
}

location @login {
    return 302 https://auth.home.example.com/auth/start?rd=$request_uri;
}
```

See [`nginx-example.conf`](nginx-example.conf) for the full annotated example.

---

## Traefik

Passage exposes `/auth/traefik` for use with Traefik's `forwardAuth` middleware.

```yaml
http:
  middlewares:
    passage-auth:
      forwardAuth:
        address: "http://passage:8080/auth/traefik"
        authResponseHeaders:
          - "X-Passage-Username"
          - "X-Passage-Email"
          - "X-Passage-Name"
          - "X-Passage-User-ID"
          - "X-Passage-Is-Admin"
        trustForwardHeader: true

  routers:
    my-app:
      rule: "Host(`myapp.home.example.com`)"
      middlewares:
        - passage-auth
      service: my-app-service
```

See [`traefik-example.yaml`](traefik-example.yaml) for the full annotated example.
