import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


def generate_ai_summary(
    analysis,
    score,
    risk_level,
    report,
):
    """
    Teknik analiz sonuçlarından Groq üzerinden
    Türkçe yönetici özeti üretir.
    """

    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv(
        "GROQ_MODEL",
        "openai/gpt-oss-20b",
    )

    if not api_key:
        return {
            "success": False,
            "summary": "",
            "error": (
                "GROQ_API_KEY bulunamadı. "
                ".env dosyasını kontrol edin."
            ),
        }

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
    )

    found_headers = [
        header_name
        for header_name, found in analysis.get(
            "security_headers",
            {},
        ).items()
        if found
    ]

    missing_headers = [
        header_name
        for header_name, found in analysis.get(
            "security_headers",
            {},
        ).items()
        if not found
    ]

    findings_text = "\n".join(
        f"- {finding}"
        for finding in report.get("findings", [])
    ) or "- Temel taramada belirgin bulgu yok."

    recommendations_text = "\n".join(
        f"- {recommendation}"
        for recommendation in report.get(
            "recommendations",
            [],
        )
    ) or "- Ek aksiyon önerisi bulunmuyor."

    prompt = f"""
Aşağıdaki sonuçlar bir vendor'ın halka açık web sitesi
üzerinde yapılan ilk güvenlik ve uyumluluk taramasına aittir.

Vendor URL: {analysis.get("url")}
Sayfa başlığı: {analysis.get("title")}
HTTP durumu: {analysis.get("status_code")}
HTTPS: {analysis.get("https")}
SSL geçerli: {analysis.get("ssl_valid")}
SSL kalan gün: {analysis.get("ssl_days_remaining")}
Privacy Policy: {analysis.get("privacy")}
Terms of Service: {analysis.get("terms")}
Contact sayfası: {analysis.get("contact")}
Bulunan güvenlik başlıkları: {found_headers}
Eksik güvenlik başlıkları: {missing_headers}
Güven puanı: {score}/100
Risk seviyesi: {risk_level}

Bulgular:
{findings_text}

Mevcut öneriler:
{recommendations_text}

Türkçe bir yönetici özeti oluştur.

Kurallar:
1. Üç kısa paragraf yaz.
2. İlk paragrafta olumlu kontrolleri özetle.
3. İkinci paragrafta eksikleri ve riskleri açıkla.
4. Son paragrafta en fazla üç öncelikli aksiyon belirt.
5. Bulguları abartma.
6. Bunun tam kapsamlı TPRM, ISO 27001, PCI-DSS veya
   GDPR denetimi olmadığını belirt.
7. Verilmeyen bilgileri uydurma.
8. Kurumun genel güvenlik seviyesini kesin olarak değerlendirme.
9. "Güvenlidir", "uyumludur", "gereksinimleri karşılar"
   gibi kesin ifadeler kullanma.
10. Bunun yerine "ilk tarama sinyalleri",
    "halka açık web sitesi katmanı",
    "ön değerlendirme" ve
    "ilk tarama puanına göre" ifadelerini kullan.
11. Risk seviyesini yalnızca mevcut teknik bulgulara dayalı
    ön değerlendirme olarak ifade et.
    12. Eksik bir güvenlik başlığını yalnızca doğrudan ilişkili olduğu risklerle eşleştir.
13. Mevcut bir kontrolün koruduğu riskleri eksikmiş gibi yazma.
14. X-Frame-Options varsa click-jacking riskini eksik kontrol olarak belirtme.
15. "Veri hırsızlığı", "ihlale yol açar", "savunmasızdır" gibi kesin ve ağır ifadeler kullanma.
16. Bunun yerine "koruma seviyesini azaltabilir", "iyileştirme alanı oluşturabilir" ve "potansiyel riski artırabilir" ifadelerini kullan.
17. Her bulguyu yalnızca gözlemlenen teknik sinyalle ilişkilendir.
Risk eşleştirme kuralları:
- HSTS eksikliği: HTTP downgrade ve zorunlu HTTPS kullanımının olmamasıyla ilişkilendir.
- CSP eksikliği: XSS ve içerik enjeksiyonu riskleriyle ilişkilendir.
- Permissions-Policy eksikliği: Tarayıcı özelliklerinin ve cihaz izinlerinin sınırlandırılmamasıyla ilişkilendir.
- X-Frame-Options mevcutsa click-jacking riskini eksik bulgu olarak yazma.
- Teknik bulgulardan kurum genelinde veri ihlali veya uyumsuzluk sonucu çıkarma.
18. Mevcut ve başarılı kontroller için ek risk yorumu üretme.
19. Bulgularla doğrudan ilişkili olmayan genel güvenlik uyarıları ekleme.
20. "Yeterli temel", "güçlü güvenlik", "güvenli yapı" gibi genel sonuç ifadeleri kullanma.
21. AI özetini maksimum 220 kelime ile sınırla.
22. Son bölümde yalnızca üç aksiyon yaz ve ek açıklama üretme.
"""

    try:
        response = client.responses.create(
            model=model,
            instructions=(
                "Sen üçüncü taraf risk yönetimi, bilgi güvenliği "
                "ve uyumluluk uzmanısın. Yalnızca verilen teknik "
                "sonuçları kullan."
            ),
            input=prompt,
        )

        return {
            "success": True,
            "summary": response.output_text,
            "error": "",
        }

    except Exception as error:
        return {
            "success": False,
            "summary": "",
            "error": str(error),
        }