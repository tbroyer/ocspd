GOAL

First goal is to play well with HAProxy, without being specific to it:
- take "bundle" PEMs as input containing the certificate chain,
  falling back to a `.issuer`-suffixed file
- output OCSP response in a `.ocsp`-suffixed file

All other usages can come later, as options if needed.

REQUIREMENTS

https://gist.github.com/sleevi/5efe9ef98961ecfb4da8

SPECIFICATIONS

- https://tools.ietf.org/html/rfc6960
- https://tools.ietf.org/html/rfc5019

FEATURES

1. `update-ocsp`: command-line tool updating OCSP responses for a set of
   certificates, replacing `openssl ocsp` or the more complete [`hapos-upd`]
   script (but without the part that's specific to HAProxy)
2. `ocspd`: long-lived program deciding when OCSP responses need to be
   refreshed, eliminating the need for a Cron job
3. both provide a _hook_ mechanism to notify applications through external
   programs (e.g. update HAProxy through the `set ssl ocsp-response` Unix
   Socket command); an `update-haproxy.sh` script is provided for HAProxy.

 [`hapos-upd`]: https://github.com/pierky/haproxy-ocsp-stapling-updater/blob/master/hapos-upd

ROADMAP

1. cleanup and iron out the library API
2. easy integration with `"crypto/tls".Config.GetCertificate` and
   `golang.org/x/crypto/acme/autocert`
