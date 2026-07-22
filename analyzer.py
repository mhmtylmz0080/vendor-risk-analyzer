import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import certifi
import requests
from bs4 import BeautifulSoup


PRIVACY_KEYWORDS = [
    "privacy",
    "privacy-policy",
    "privacy-notice",
    "gdpr",
    "kvkk",
    "personal-data",
]

TERMS_KEYWORDS = [
    "terms",
    "terms-of-service",
    "conditions",
    "legal",
    "tos",
    "user-agreement",
]

CONTACT_KEYWORDS = [
    "contact",
    "contact-us",
    "support",
    "help",
    "reach-us",
]

SECURITY_HEADERS = {
    "HSTS": "Strict-Transport-Security",
    "Content Security Policy": "Content-Security-Policy",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


def contains_keyword(links, keywords):
    return any(
        keyword in link
        for link in links
        for keyword in keywords
    )


def normalize_url(vendor_url):
    vendor_url = vendor_url.strip()

    if not vendor_url.startswith(("http://", "https://")):
        vendor_url = "https://" + vendor_url

    return vendor_url


def get_certificate_value(cert_section, field_name):
    """
    SSL sertifikasındaki subject veya issuer alanlarından
    istenen değeri çıkarır.
    """

    for item_group in cert_section:
        for key, value in item_group:
            if key == field_name:
                return value

    return "Bilinmiyor"


def analyze_ssl_certificate(url):
    """
    HTTPS sitesinin SSL sertifikasını kontrol eder.
    """

    parsed_url = urlparse(url)

    if parsed_url.scheme.lower() != "https":
        return {
            "ssl_valid": False,
            "ssl_subject": "Bilinmiyor",
            "ssl_issuer": "Bilinmiyor",
            "ssl_not_before": "",
            "ssl_not_after": "",
            "ssl_days_remaining": None,
            "ssl_error": "Website HTTPS kullanmıyor.",
        }

    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    if not hostname:
        return {
            "ssl_valid": False,
            "ssl_subject": "Bilinmiyor",
            "ssl_issuer": "Bilinmiyor",
            "ssl_not_before": "",
            "ssl_not_after": "",
            "ssl_days_remaining": None,
            "ssl_error": "Hostname bulunamadı.",
        }

    try:
        context = ssl.create_default_context(
    cafile=certifi.where()
)

        with socket.create_connection(
            (hostname, port),
            timeout=10,
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=hostname,
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

        not_before_timestamp = ssl.cert_time_to_seconds(
            certificate["notBefore"]
        )

        not_after_timestamp = ssl.cert_time_to_seconds(
            certificate["notAfter"]
        )

        not_before = datetime.fromtimestamp(
            not_before_timestamp,
            timezone.utc,
        )

        not_after = datetime.fromtimestamp(
            not_after_timestamp,
            timezone.utc,
        )

        now = datetime.now(timezone.utc)

        days_remaining = (not_after - now).days

        ssl_valid = (
            not_before <= now <= not_after
            and days_remaining >= 0
        )

        subject = get_certificate_value(
            certificate.get("subject", ()),
            "commonName",
        )

        issuer = get_certificate_value(
            certificate.get("issuer", ()),
            "organizationName",
        )

        if issuer == "Bilinmiyor":
            issuer = get_certificate_value(
                certificate.get("issuer", ()),
                "commonName",
            )

        return {
            "ssl_valid": ssl_valid,
            "ssl_subject": subject,
            "ssl_issuer": issuer,
            "ssl_not_before": not_before.strftime(
                "%d.%m.%Y %H:%M UTC"
            ),
            "ssl_not_after": not_after.strftime(
                "%d.%m.%Y %H:%M UTC"
            ),
            "ssl_days_remaining": days_remaining,
            "ssl_error": "",
        }

    except ssl.SSLCertVerificationError as error:
        return {
            "ssl_valid": False,
            "ssl_subject": "Bilinmiyor",
            "ssl_issuer": "Bilinmiyor",
            "ssl_not_before": "",
            "ssl_not_after": "",
            "ssl_days_remaining": None,
            "ssl_error": f"Sertifika doğrulanamadı: {error}",
        }

    except Exception as error:
        return {
            "ssl_valid": False,
            "ssl_subject": "Bilinmiyor",
            "ssl_issuer": "Bilinmiyor",
            "ssl_not_before": "",
            "ssl_not_after": "",
            "ssl_days_remaining": None,
            "ssl_error": str(error),
        }


def analyze_vendor(vendor_url):
    requested_url = normalize_url(vendor_url)

    response = requests.get(
        requested_url,
        timeout=10,
        headers={
            "User-Agent": (
                "Mozilla/5.0 "
                "(Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        },
        allow_redirects=True,
    )

    response.raise_for_status()

    final_url = response.url

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    else:
        title = "Başlık bulunamadı"

    links = []

    for link in soup.find_all("a"):
        href = link.get("href")

        if href:
            links.append(href.lower())

    privacy_found = contains_keyword(
        links,
        PRIVACY_KEYWORDS,
    )

    terms_found = contains_keyword(
        links,
        TERMS_KEYWORDS,
    )

    contact_found = contains_keyword(
        links,
        CONTACT_KEYWORDS,
    )

    security_headers = {}

    for display_name, header_name in SECURITY_HEADERS.items():
        security_headers[display_name] = bool(
            response.headers.get(header_name)
        )

    security_header_count = sum(
        security_headers.values()
    )

    ssl_analysis = analyze_ssl_certificate(final_url)

    return {
        "requested_url": requested_url,
        "url": final_url,
        "title": title,
        "status_code": response.status_code,
        "server": response.headers.get("Server", ""),
        "https": final_url.lower().startswith("https://"),
        "privacy": privacy_found,
        "terms": terms_found,
        "contact": contact_found,
        "security_headers": security_headers,
        "security_header_count": security_header_count,
        "security_header_total": len(SECURITY_HEADERS),
        "links": links,
        **ssl_analysis,
    }