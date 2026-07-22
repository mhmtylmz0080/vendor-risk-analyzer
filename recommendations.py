def generate_findings(analysis):
    """
    Analiz sonuçlarından bulgu ve öneri listeleri üretir.
    """

    findings = []
    recommendations = []

    # HTTPS
    if not analysis.get("https"):
        findings.append(
            "Website HTTPS kullanmıyor."
        )
        recommendations.append(
            "Tüm web trafiğini HTTPS üzerinden sunun ve "
            "HTTP isteklerini HTTPS adresine yönlendirin."
        )

    # SSL
    if not analysis.get("ssl_valid"):
        findings.append(
            "SSL sertifikası geçersiz veya doğrulanamadı."
        )
        recommendations.append(
            "SSL sertifika zincirini, geçerlilik süresini ve "
            "domain eşleşmesini kontrol edin."
        )

    ssl_days_remaining = analysis.get(
        "ssl_days_remaining"
    )

    if (
        ssl_days_remaining is not None
        and ssl_days_remaining < 30
    ):
        findings.append(
            f"SSL sertifikasının bitmesine yalnızca "
            f"{ssl_days_remaining} gün kaldı."
        )
        recommendations.append(
            "SSL sertifikasını süresi dolmadan yenileyin ve "
            "otomatik yenileme sürecini doğrulayın."
        )

    # Security Headers
    security_headers = analysis.get(
        "security_headers",
        {}
    )

    header_recommendations = {
        "HSTS": (
            "Strict-Transport-Security başlığını etkinleştirin. "
            "Bu başlık tarayıcıların yalnızca HTTPS kullanmasını sağlar."
        ),
        "Content Security Policy": (
            "Content-Security-Policy tanımlayın. "
            "Bu kontrol XSS ve içerik enjeksiyonu risklerini azaltır."
        ),
        "X-Frame-Options": (
            "X-Frame-Options başlığını SAMEORIGIN veya DENY "
            "değeriyle yapılandırın."
        ),
        "X-Content-Type-Options": (
            "X-Content-Type-Options başlığını nosniff "
            "değeriyle yapılandırın."
        ),
        "Referrer-Policy": (
            "Referrer-Policy tanımlayarak tarayıcıların hangi "
            "referans bilgilerini paylaşacağını sınırlandırın."
        ),
        "Permissions-Policy": (
            "Permissions-Policy başlığıyla kamera, mikrofon ve "
            "konum gibi tarayıcı yetkilerini sınırlandırın."
        ),
    }

    for header_name, header_found in security_headers.items():
        if not header_found:
            findings.append(
                f"{header_name} güvenlik başlığı bulunamadı."
            )

            recommendation = header_recommendations.get(
                header_name
            )

            if recommendation:
                recommendations.append(
                    recommendation
                )

    # Compliance pages
    if not analysis.get("privacy"):
        findings.append(
            "Privacy Policy bağlantısı tespit edilemedi."
        )
        recommendations.append(
            "Kullanıcıların kolayca erişebileceği bir gizlilik "
            "politikası yayımlayın."
        )

    if not analysis.get("terms"):
        findings.append(
            "Terms of Service bağlantısı tespit edilemedi."
        )
        recommendations.append(
            "Hizmet kullanım koşullarını açıkça belirten bir "
            "Terms of Service sayfası yayımlayın."
        )

    if not analysis.get("contact"):
        findings.append(
            "Contact veya Support bağlantısı tespit edilemedi."
        )
        recommendations.append(
            "Güvenlik ve uyumluluk bildirimleri için erişilebilir "
            "bir iletişim veya destek kanalı sunun."
        )

    return {
        "findings": findings,
        "recommendations": recommendations,
    }