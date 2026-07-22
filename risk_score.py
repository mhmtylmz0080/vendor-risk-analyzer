def calculate_score_breakdown(analysis):
    """
    Analiz sonucuna göre her kriterin aldığı
    puanı ve maksimum puanı hesaplar.
    """

    breakdown = []

    https_score = 10 if analysis.get("https") else 0

    breakdown.append(
        {
            "criterion": "HTTPS Kullanımı",
            "score": https_score,
            "max_score": 10,
            "description": (
                "Web sitesinin HTTPS üzerinden "
                "erişilebilir olması."
            ),
        }
    )

    status_code = analysis.get("status_code")

    http_score = (
        10
        if status_code
        and 200 <= status_code < 300
        else 0
    )

    breakdown.append(
        {
            "criterion": "HTTP Yanıtı",
            "score": http_score,
            "max_score": 10,
            "description": (
                "Web sitesinin başarılı bir "
                "2xx HTTP yanıtı vermesi."
            ),
        }
    )

    ssl_score = 0
    ssl_description = (
        "SSL sertifikası geçersiz veya "
        "doğrulanamadı."
    )

    if analysis.get("ssl_valid"):
        days_remaining = analysis.get(
            "ssl_days_remaining"
        )

        if (
            days_remaining is not None
            and days_remaining >= 30
        ):
            ssl_score = 15
            ssl_description = (
                "SSL sertifikası geçerli ve "
                "30 günden fazla süresi var."
            )

        else:
            ssl_score = 5
            ssl_description = (
                "SSL sertifikası geçerli ancak "
                "30 günden az süresi kalmış."
            )

    breakdown.append(
        {
            "criterion": "SSL Sertifikası",
            "score": ssl_score,
            "max_score": 15,
            "description": ssl_description,
        }
    )

    privacy_score = (
        15
        if analysis.get("privacy")
        else 0
    )

    breakdown.append(
        {
            "criterion": "Privacy Policy",
            "score": privacy_score,
            "max_score": 15,
            "description": (
                "Web sitesinde gizlilik "
                "politikasının bulunması."
            ),
        }
    )

    terms_score = (
        10
        if analysis.get("terms")
        else 0
    )

    breakdown.append(
        {
            "criterion": "Terms of Service",
            "score": terms_score,
            "max_score": 10,
            "description": (
                "Web sitesinde kullanım şartları "
                "sayfasının bulunması."
            ),
        }
    )

    contact_score = (
        10
        if analysis.get("contact")
        else 0
    )

    breakdown.append(
        {
            "criterion": "Contact Sayfası",
            "score": contact_score,
            "max_score": 10,
            "description": (
                "Web sitesinde iletişim "
                "sayfasının bulunması."
            ),
        }
    )

    title = analysis.get("title")

    title_score = (
        5
        if title and title.strip()
        else 0
    )

    breakdown.append(
        {
            "criterion": "Sayfa Başlığı",
            "score": title_score,
            "max_score": 5,
            "description": (
                "Web sitesinde tanımlı bir "
                "sayfa başlığının bulunması."
            ),
        }
    )

    security_header_count = analysis.get(
        "security_header_count",
        0,
    )

    security_header_total = analysis.get(
        "security_header_total",
        6,
    )

    if security_header_total > 0:
        security_header_score = round(
            (
                security_header_count
                / security_header_total
            )
            * 25
        )
    else:
        security_header_score = 0

    breakdown.append(
        {
            "criterion": "Güvenlik Başlıkları",
            "score": security_header_score,
            "max_score": 25,
            "description": (
                f"{security_header_count} / "
                f"{security_header_total} güvenlik "
                "başlığı tespit edildi."
            ),
        }
    )

    return breakdown


def calculate_score(analysis):
    """
    Bütün kriterlerin puanlarını toplar.
    """

    breakdown = calculate_score_breakdown(
        analysis
    )

    total_score = sum(
        item["score"]
        for item in breakdown
    )

    return min(total_score, 100)


def determine_risk_level(score):
    """
    Güven puanına göre risk seviyesini belirler.
    """

    if score >= 85:
        return "🟢 DÜŞÜK RİSK"

    if score >= 60:
        return "🟠 ORTA RİSK"

    return "🔴 YÜKSEK RİSK"


def get_scoring_criteria():
    """
    Uygulamanın ilk ekranında gösterilecek
    değerlendirme kriterlerini döndürür.
    """

    return [
        {
            "Kriter": "HTTPS Kullanımı",
            "Maksimum Puan": 10,
            "Açıklama": (
                "Web sitesinin HTTPS üzerinden "
                "erişilebilir olması."
            ),
        },
        {
            "Kriter": "HTTP Yanıtı",
            "Maksimum Puan": 10,
            "Açıklama": (
                "Başarılı bir 2xx HTTP yanıtı."
            ),
        },
        {
            "Kriter": "SSL Sertifikası",
            "Maksimum Puan": 15,
            "Açıklama": (
                "Geçerli ve süresi yeterli "
                "SSL sertifikası."
            ),
        },
        {
            "Kriter": "Privacy Policy",
            "Maksimum Puan": 15,
            "Açıklama": (
                "Gizlilik politikası sayfasının "
                "bulunması."
            ),
        },
        {
            "Kriter": "Terms of Service",
            "Maksimum Puan": 10,
            "Açıklama": (
                "Kullanım şartları sayfasının "
                "bulunması."
            ),
        },
        {
            "Kriter": "Contact Sayfası",
            "Maksimum Puan": 10,
            "Açıklama": (
                "İletişim sayfasının bulunması."
            ),
        },
        {
            "Kriter": "Sayfa Başlığı",
            "Maksimum Puan": 5,
            "Açıklama": (
                "Web sitesinde sayfa başlığı "
                "bulunması."
            ),
        },
        {
            "Kriter": "Güvenlik Başlıkları",
            "Maksimum Puan": 25,
            "Açıklama": (
                "Altı temel güvenlik başlığının "
                "uygulanması."
            ),
        },
    ]