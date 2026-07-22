import pandas as pd
import requests
import streamlit as st

from ai_summary import generate_ai_summary
from analyzer import analyze_vendor
from database import (
    format_chart_date,
    format_created_at,
    get_analysis_by_id,
    get_analysis_history,
    get_vendor_score_history,
    init_database,
    save_analysis,
    update_ai_summary,
)
from recommendations import generate_findings
from risk_score import (
    calculate_score,
    calculate_score_breakdown,
    determine_risk_level,
    get_scoring_criteria,
)


st.set_page_config(
    page_title="Vendor Risk Analyzer",
    page_icon="🛡️",
    layout="centered",
)


init_database()


SESSION_DEFAULTS = {
    "analysis": None,
    "score": None,
    "risk_level": None,
    "report": None,
    "ai_summary": None,
    "ai_error": None,
    "analysis_id": None,
}


for key, default_value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default_value


def show_boolean_result(label, result):
    """
    Boolean kontrolleri kullanıcı dostu biçimde gösterir.
    """

    st.write(
        f"**{label}:**",
        "✅ Var" if result else "❌ Bulunamadı",
    )


def get_change_text(change):
    """
    Skor değişimini kullanıcı dostu metne dönüştürür.
    """

    if change > 0:
        return f"🟢 +{change} İyileşti"

    if change < 0:
        return f"🔴 {change} Kötüleşti"

    return "⚪ 0 Değişmedi"


def render_score_breakdown(analysis, score):
    """
    Analizin puan kırılımını gösterir.
    """

    st.subheader("🧮 Puan Kırılımı")

    score_breakdown = calculate_score_breakdown(
        analysis
    )

    breakdown_table = []

    for item in score_breakdown:
        lost_score = (
            item["max_score"]
            - item["score"]
        )

        breakdown_table.append(
            {
                "Değerlendirme Kriteri": (
                    item["criterion"]
                ),
                "Alınan Puan": (
                    f"{item['score']} / "
                    f"{item['max_score']}"
                ),
                "Kaybedilen Puan": lost_score,
                "Açıklama": item["description"],
            }
        )

    st.dataframe(
        breakdown_table,
        use_container_width=True,
        hide_index=True,
    )

    total_lost_score = 100 - score

    if total_lost_score > 0:
        st.warning(
            f"Toplam {total_lost_score} puan, "
            f"eksik veya yetersiz kontroller "
            f"nedeniyle alınamadı."
        )

    else:
        st.success(
            "Tüm değerlendirme kriterlerinden "
            "tam puan alındı."
        )


def render_current_analysis():
    """
    Yeni analiz sekmesindeki mevcut sonucu gösterir.
    """

    analysis = st.session_state.analysis
    score = st.session_state.score
    risk_level = st.session_state.risk_level
    report = st.session_state.report

    if analysis is None:
        return

    st.success(
        "✅ Site başarıyla analiz edildi."
    )

    st.subheader("📋 Genel Bilgiler")

    st.write(
        "**Analiz Edilen Website:**",
        analysis["url"],
    )

    requested_url = analysis.get(
        "requested_url",
        analysis["url"],
    )

    if requested_url != analysis["url"]:
        st.info(
            "Website farklı bir adrese yönlendirdi: "
            f"{analysis['url']}"
        )

    st.write(
        "**Sayfa Başlığı:**",
        analysis.get("title")
        or "Bilinmiyor",
    )

    st.write(
        "**HTTP Durumu:**",
        analysis.get("status_code")
        or "Bilinmiyor",
    )

    st.write(
        "**Server:**",
        analysis.get("server")
        or "Bilinmiyor",
    )

    st.subheader(
        "🔒 Temel Güvenlik Kontrolleri"
    )

    st.write(
        "**HTTPS:**",
        (
            "✅ Kullanılıyor"
            if analysis.get("https")
            else "❌ Kullanılmıyor"
        ),
    )

    st.subheader("🔐 SSL Sertifikası")

    if analysis.get("ssl_valid"):
        st.write(
            "**Sertifika Durumu:**",
            "✅ Geçerli",
        )

        st.write(
            "**Sertifika Sahibi:**",
            analysis.get("ssl_subject")
            or "Bilinmiyor",
        )

        st.write(
            "**Sertifikayı Veren Kuruluş:**",
            analysis.get("ssl_issuer")
            or "Bilinmiyor",
        )

        st.write(
            "**Başlangıç Tarihi:**",
            analysis.get("ssl_not_before")
            or "Bilinmiyor",
        )

        st.write(
            "**Bitiş Tarihi:**",
            analysis.get("ssl_not_after")
            or "Bilinmiyor",
        )

        days_remaining = analysis.get(
            "ssl_days_remaining"
        )

        if days_remaining is not None:
            st.write(
                "**Kalan Süre:**",
                f"{days_remaining} gün",
            )

            if days_remaining < 30:
                st.warning(
                    "⚠️ SSL sertifikasının bitmesine "
                    "30 günden az kaldı."
                )

    else:
        st.write(
            "**Sertifika Durumu:**",
            "⚠️ Geçersiz veya doğrulanamadı",
        )

        ssl_error = analysis.get(
            "ssl_error"
        )

        if ssl_error:
            st.code(ssl_error)

    st.subheader("🛡️ Güvenlik Başlıkları")

    security_headers = analysis.get(
        "security_headers",
        {},
    )

    for header_name, header_found in (
        security_headers.items()
    ):
        st.write(
            f"**{header_name}:**",
            (
                "✅ Var"
                if header_found
                else "❌ Bulunamadı"
            ),
        )

    security_header_count = analysis.get(
        "security_header_count",
        0,
    )

    security_header_total = analysis.get(
        "security_header_total",
        len(security_headers),
    )

    st.write(
        "**Güvenlik Başlığı Sonucu:**",
        (
            f"{security_header_count} / "
            f"{security_header_total}"
        ),
    )

    st.subheader("📑 Uyumluluk Kontrolleri")

    show_boolean_result(
        "Privacy Policy",
        analysis.get("privacy"),
    )

    show_boolean_result(
        "Terms of Service",
        analysis.get("terms"),
    )

    show_boolean_result(
        "Contact",
        analysis.get("contact"),
    )

    st.subheader("📊 İlk Tarama Sonucu")

    metric_column, risk_column = st.columns(
        2
    )

    with metric_column:
        st.metric(
            label="Güven Puanı",
            value=f"{score} / 100",
        )

    with risk_column:
        st.metric(
            label="Risk Seviyesi",
            value=risk_level,
        )

    render_score_breakdown(
        analysis=analysis,
        score=score,
    )

    st.subheader("⚠️ Bulgular")

    if report["findings"]:
        for finding in report["findings"]:
            st.warning(finding)

    else:
        st.success(
            "Temel web taramasında kritik bir "
            "bulgu tespit edilmedi."
        )

    st.subheader("💡 Aksiyon Önerileri")

    if report["recommendations"]:
        for index, recommendation in enumerate(
            report["recommendations"],
            start=1,
        ):
            st.write(
                f"**{index}.** {recommendation}"
            )

    else:
        st.success(
            "Mevcut kontroller için ek bir "
            "aksiyon önerisi bulunmuyor."
        )

    st.subheader(
        "🤖 AI Risk Değerlendirmesi"
    )

    st.write(
        "Teknik bulguların yönetici seviyesinde "
        "özetlenmesi için AI değerlendirmesi "
        "oluşturun."
    )

    if st.button(
        "AI Özeti Oluştur",
        key="generate_ai_summary",
    ):
        st.session_state.ai_error = None

        with st.spinner(
            "AI risk değerlendirmesi "
            "hazırlanıyor..."
        ):
            ai_result = generate_ai_summary(
                analysis=analysis,
                score=score,
                risk_level=risk_level,
                report=report,
            )

        if ai_result["success"]:
            st.session_state.ai_summary = (
                ai_result["summary"]
            )

            analysis_id = (
                st.session_state.analysis_id
            )

            if analysis_id is not None:
                update_ai_summary(
                    analysis_id,
                    ai_result["summary"],
                )

        else:
            st.session_state.ai_summary = None
            st.session_state.ai_error = (
                ai_result["error"]
            )

    if st.session_state.ai_summary:
        st.info(
            st.session_state.ai_summary
        )

    if st.session_state.ai_error:
        st.error(
            "AI özeti oluşturulamadı."
        )

        st.code(
            st.session_state.ai_error
        )

    st.caption(
        "Bu sonuç yalnızca halka açık web sitesi "
        "sinyallerine dayanan bir ön değerlendirmedir. "
        "Tam kapsamlı bir TPRM, ISO 27001, PCI-DSS "
        "veya GDPR denetimi değildir."
    )


st.title("🛡️ Vendor Risk Analyzer")

st.write(
    "Vendor web sitesini girerek temel güvenlik "
    "ve uyumluluk analizini başlatın."
)


with st.expander(
    "📊 Değerlendirme Kriterleri ve Puanlama"
):
    st.write(
        "Vendor güven puanı aşağıdaki kriterlere "
        "göre 100 puan üzerinden hesaplanır."
    )

    scoring_criteria = get_scoring_criteria()

    st.dataframe(
        scoring_criteria,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "Bu puanlama yalnızca halka açık web "
        "sitesi sinyallerine dayanmaktadır."
    )


analysis_tab, history_tab = st.tabs(
    [
        "🔍 Yeni Analiz",
        "📚 Analiz Geçmişi",
    ]
)


with analysis_tab:
    vendor_url = st.text_input(
        "Vendor Website",
        placeholder="https://company.com",
    )

    if st.button(
        "Analiz Et",
        type="primary",
    ):
        if not vendor_url.strip():
            st.warning(
                "Lütfen bir web sitesi adresi girin."
            )

        else:
            try:
                with st.spinner(
                    "Vendor analiz ediliyor..."
                ):
                    analysis = analyze_vendor(
                        vendor_url
                    )

                    score = calculate_score(
                        analysis
                    )

                    risk_level = (
                        determine_risk_level(
                            score
                        )
                    )

                    report = generate_findings(
                        analysis
                    )

                    analysis_id = save_analysis(
                        analysis=analysis,
                        score=score,
                        risk_level=risk_level,
                        report=report,
                    )

                st.session_state.analysis = (
                    analysis
                )

                st.session_state.score = score

                st.session_state.risk_level = (
                    risk_level
                )

                st.session_state.report = report

                st.session_state.analysis_id = (
                    analysis_id
                )

                st.session_state.ai_summary = None
                st.session_state.ai_error = None

            except requests.exceptions.Timeout:
                st.error(
                    "❌ Web sitesi belirlenen süre "
                    "içinde yanıt vermedi."
                )

            except requests.exceptions.HTTPError as error:
                st.error(
                    "❌ Web sitesi başarılı bir "
                    "HTTP yanıtı vermedi."
                )

                st.code(str(error))

            except requests.exceptions.SSLError as error:
                st.error(
                    "❌ Web sitesinin SSL sertifikası "
                    "doğrulanamadı."
                )

                st.code(str(error))

            except requests.exceptions.RequestException as error:
                st.error(
                    "❌ Web sitesine bağlantı "
                    "kurulamadı."
                )

                st.code(str(error))

            except Exception as error:
                st.error(
                    "❌ Analiz sırasında beklenmeyen "
                    "bir hata oluştu."
                )

                st.code(str(error))

    render_current_analysis()


with history_tab:
    history = get_analysis_history()

    if not history:
        st.info(
            "Henüz kaydedilmiş bir analiz "
            "bulunmuyor."
        )

    else:
        st.subheader("Son Analizler")

        table_data = []

        for item in history:
            table_data.append(
                {
                    "ID": item["id"],
                    "Website": item["url"],
                    "Güven Puanı": (
                        item["score"]
                    ),
                    "Risk Seviyesi": (
                        item["risk_level"]
                    ),
                    "SSL": (
                        "Geçerli"
                        if item["ssl_valid"]
                        else "Geçersiz"
                    ),
                    "Güvenlik Başlıkları": (
                        f"{item['security_header_count']} "
                        f"/ "
                        f"{item['security_header_total']}"
                    ),
                    "Analiz Tarihi": (
                        format_created_at(
                            item["created_at"]
                        )
                    ),
                }
            )

        st.dataframe(
            table_data,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("📈 Vendor Skor Trendi")

        vendor_urls = list(
            dict.fromkeys(
                item["url"]
                for item in history
            )
        )

        selected_vendor_url = st.selectbox(
            "Trendini görüntülemek istediğiniz vendor",
            options=vendor_urls,
            key="trend_vendor_url",
        )

        vendor_score_history = (
            get_vendor_score_history(
                selected_vendor_url
            )
        )

        if vendor_score_history:
            current_score = (
                vendor_score_history[-1]["score"]
            )

            previous_score = None
            score_change = 0

            if len(vendor_score_history) >= 2:
                previous_score = (
                    vendor_score_history[-2][
                        "score"
                    ]
                )

                score_change = (
                    current_score
                    - previous_score
                )

            (
                current_column,
                previous_column,
                change_column,
            ) = st.columns(3)

            with current_column:
                st.metric(
                    "Güncel Skor",
                    f"{current_score}/100",
                )

            with previous_column:
                st.metric(
                    "Önceki Skor",
                    (
                        f"{previous_score}/100"
                        if previous_score
                        is not None
                        else "Yok"
                    ),
                )

            with change_column:
                st.metric(
                    "Değişim",
                    (
                        f"{score_change:+d}"
                        if previous_score
                        is not None
                        else "Yok"
                    ),
                )

            if previous_score is not None:
                if score_change > 0:
                    st.success(
                        f"🟢 Skor {score_change} "
                        f"puan iyileşti."
                    )

                elif score_change < 0:
                    st.error(
                        f"🔴 Skor "
                        f"{abs(score_change)} "
                        f"puan düştü."
                    )

                else:
                    st.info(
                        "⚪ Önceki analize göre "
                        "skor değişmedi."
                    )

            trend_data = []
            previous_trend_score = None

            for trend_item in (
                vendor_score_history
            ):
                trend_score = (
                    trend_item["score"]
                )

                if previous_trend_score is None:
                    change_text = "İlk analiz"

                else:
                    change = (
                        trend_score
                        - previous_trend_score
                    )

                    change_text = (
                        get_change_text(change)
                    )

                trend_data.append(
                    {
                        "Analiz Tarihi": (
                            format_chart_date(
                                trend_item[
                                    "created_at"
                                ]
                            )
                        ),
                        "Güven Puanı": (
                            trend_score
                        ),
                        "Değişim": change_text,
                        "Risk Seviyesi": (
                            trend_item[
                                "risk_level"
                            ]
                        ),
                    }
                )

                previous_trend_score = (
                    trend_score
                )

            trend_dataframe = pd.DataFrame(
                trend_data
            )

            chart_dataframe = (
                trend_dataframe[
                    [
                        "Analiz Tarihi",
                        "Güven Puanı",
                    ]
                ]
                .set_index("Analiz Tarihi")
            )

            st.line_chart(
                chart_dataframe,
                y="Güven Puanı",
            )

            st.dataframe(
                trend_dataframe,
                use_container_width=True,
                hide_index=True,
            )

            if len(vendor_score_history) < 2:
                st.info(
                    "Trend oluşması için bu vendor'ı "
                    "en az bir kez daha analiz edin."
                )

        else:
            st.info(
                "Bu vendor için geçmiş analiz "
                "bulunamadı."
            )

        st.divider()

        analysis_ids = [
            item["id"]
            for item in history
        ]

        def format_analysis_option(
            analysis_id,
        ):
            for item in history:
                if item["id"] == analysis_id:
                    return (
                        f"#{item['id']} - "
                        f"{item['url']} - "
                        f"{item['score']}/100"
                    )

            return str(analysis_id)

        selected_analysis_id = st.selectbox(
            "Analiz detayını görüntüle",
            options=analysis_ids,
            format_func=format_analysis_option,
        )

        selected_analysis = (
            get_analysis_by_id(
                selected_analysis_id
            )
        )

        if selected_analysis:
            st.divider()

            st.subheader(
                f"Analiz "
                f"#{selected_analysis['id']}"
            )

            st.write(
                "**Website:**",
                selected_analysis["url"],
            )

            st.write(
                "**Sayfa Başlığı:**",
                selected_analysis.get(
                    "title"
                )
                or "Bilinmiyor",
            )

            st.write(
                "**HTTP Durumu:**",
                selected_analysis.get(
                    "status_code"
                )
                or "Bilinmiyor",
            )

            st.write(
                "**Güven Puanı:**",
                (
                    f"{selected_analysis['score']} "
                    f"/ 100"
                ),
            )

            st.write(
                "**Risk Seviyesi:**",
                selected_analysis[
                    "risk_level"
                ],
            )

            st.write(
                "**Analiz Tarihi:**",
                format_created_at(
                    selected_analysis[
                        "created_at"
                    ]
                ),
            )

            st.write(
                "**SSL Durumu:**",
                (
                    "✅ Geçerli"
                    if selected_analysis[
                        "ssl_valid"
                    ]
                    else "❌ Geçersiz"
                ),
            )

            ssl_days_remaining = (
                selected_analysis.get(
                    "ssl_days_remaining"
                )
            )

            if ssl_days_remaining is not None:
                st.write(
                    "**SSL Kalan Süre:**",
                    (
                        f"{ssl_days_remaining} "
                        f"gün"
                    ),
                )

            history_analysis = {
                "https": bool(
                    selected_analysis.get(
                        "https"
                    )
                ),
                "status_code": (
                    selected_analysis.get(
                        "status_code"
                    )
                ),
                "ssl_valid": bool(
                    selected_analysis.get(
                        "ssl_valid"
                    )
                ),
                "ssl_days_remaining": (
                    selected_analysis.get(
                        "ssl_days_remaining"
                    )
                ),
                "privacy": bool(
                    selected_analysis.get(
                        "privacy"
                    )
                ),
                "terms": bool(
                    selected_analysis.get(
                        "terms"
                    )
                ),
                "contact": bool(
                    selected_analysis.get(
                        "contact"
                    )
                ),
                "title": (
                    selected_analysis.get(
                        "title"
                    )
                ),
                "security_header_count": (
                    selected_analysis.get(
                        "security_header_count",
                        0,
                    )
                ),
                "security_header_total": (
                    selected_analysis.get(
                        "security_header_total",
                        6,
                    )
                ),
            }

            render_score_breakdown(
                analysis=history_analysis,
                score=selected_analysis[
                    "score"
                ],
            )

            st.subheader(
                "🛡️ Güvenlik Başlıkları"
            )

            security_headers = (
                selected_analysis.get(
                    "security_headers",
                    {},
                )
            )

            for (
                header_name,
                header_found,
            ) in security_headers.items():
                st.write(
                    f"**{header_name}:**",
                    (
                        "✅ Var"
                        if header_found
                        else "❌ Bulunamadı"
                    ),
                )

            st.subheader(
                "📑 Uyumluluk Kontrolleri"
            )

            show_boolean_result(
                "Privacy Policy",
                selected_analysis.get(
                    "privacy"
                ),
            )

            show_boolean_result(
                "Terms of Service",
                selected_analysis.get(
                    "terms"
                ),
            )

            show_boolean_result(
                "Contact",
                selected_analysis.get(
                    "contact"
                ),
            )

            st.subheader("⚠️ Bulgular")

            if selected_analysis["findings"]:
                for finding in (
                    selected_analysis[
                        "findings"
                    ]
                ):
                    st.warning(finding)

            else:
                st.success(
                    "Kayıtlı bulgu bulunmuyor."
                )

            st.subheader("💡 Öneriler")

            recommendations = (
                selected_analysis[
                    "recommendations"
                ]
            )

            if recommendations:
                for (
                    index,
                    recommendation,
                ) in enumerate(
                    recommendations,
                    start=1,
                ):
                    st.write(
                        f"**{index}.** "
                        f"{recommendation}"
                    )

            else:
                st.success(
                    "Kayıtlı öneri bulunmuyor."
                )

            if selected_analysis.get(
                "ai_summary"
            ):
                st.subheader(
                    "🤖 AI Risk Değerlendirmesi"
                )

                st.info(
                    selected_analysis[
                        "ai_summary"
                    ]
                )