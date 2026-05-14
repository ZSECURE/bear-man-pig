# bear-man-pig

A minimal static web tool for checking common email security records:

- SPF
- DKIM
- DMARC
- TLS-RPT
- MTA-STS

## Run locally

Because the app is fully static, you can serve it with any web server. For example:

```bash
cd /home/runner/work/bear-man-pig/bear-man-pig
python3 -m http.server 8000
```

Then open <http://localhost:8000>.

## Notes

- DNS lookups use public DNS-over-HTTPS resolvers in the browser.
- DKIM discovery is selector-based, so the UI supports an optional comma-separated selector list and also tries a small default list.
- TLS is checked via the `_smtp._tls` TLS-RPT TXT record.
- MTA-STS is checked via the `_mta-sts` TXT record and then attempts to fetch the published policy file. Some domains may block cross-origin policy fetches from browsers, in which case the app reports that limitation.
