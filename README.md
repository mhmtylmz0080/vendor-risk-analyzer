# Vendor Risk Analyzer

Vendor Risk Analyzer, halka açık web sitesi sinyallerini kullanarak
üçüncü taraf vendor güvenlik ve uyumluluk ön değerlendirmesi yapan
Streamlit tabanlı bir PoC uygulamasıdır.

## Özellikler

- HTTPS ve HTTP durum kontrolü
- SSL sertifikası doğrulama ve kalan süre analizi
- Güvenlik başlığı kontrolü
- Privacy Policy, Terms of Service ve Contact sayfası kontrolü
- 100 üzerinden güven puanı
- Kriter bazlı puan kırılımı
- Bulgular ve aksiyon önerileri
- AI destekli yönetici özeti
- SQLite analiz geçmişi
- Vendor skor trendi ve değişim takibi

## Değerlendirilen Güvenlik Başlıkları

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Kurulum

```bash
git clone https://github.com/mhmtylmz0080/vendor-risk-analyzer.git
cd vendor-risk-analyzer

python3 -m venv .venv
source .venv/bin/activate

pip install streamlit pandas requests beautifulsoup4 certifi python-dotenv openai