"""Minimal first-journey KO/EN UI localization support.

This deliberately does not claim full-product i18n. Korean remains the default.
"""
from __future__ import annotations

UI_LANGUAGE_COOKIE = "vulnflow_lang"
SUPPORTED_UI_LANGUAGES = {"ko", "en"}
LOCALIZED_TEMPLATES = {
    "login.html",
    "dashboard.html",
    "upload.html",
    "import_preview.html",
    "finding.html",
}

_DYNAMIC_EN = {
    "취약점 결과를 반영했습니다.": "Vulnerability results were imported.",
    "유효한 취약점만 반영했습니다. 제외된 행은 가져오기 오류 CSV에서 확인하세요.": "Only valid findings were imported. Review excluded rows in the import error CSV.",
    "현재 열 매핑으로 다시 검사했습니다.": "The file was rechecked with the current column mapping.",
    "오류가 남아 있습니다. 매핑을 수정하거나 유효한 행만 가져오기를 선택하세요.": "Errors remain. Fix the mapping or choose to import only valid rows.",
    "전체 결과 대조에서는 오류 행을 건너뛸 수 없습니다. 누락 판정을 막기 위해 모든 오류를 먼저 해결하세요.": "Snapshot mode cannot skip invalid rows. Resolve all errors first to avoid incorrect absence decisions.",
    "처리 전": "Open",
    "조치 중": "In progress",
    "확인 요청": "Ready for verification",
    "예외 승인": "Risk accepted",
    "완료": "Closed",
    "즉시 조치": "Immediate action",
    "긴급 검토": "Urgent review",
    "예정 조치": "Scheduled",
    "관찰": "Monitor",
    "제품": "Product",
    "자산": "Asset",
    "설명": "Description",
    "버전": "Version",
    "컴포넌트": "Component",
    "환경": "Environment",
    "담당자": "Owner",
    "목표일": "Due date",
    "인터넷 노출": "Internet exposed",
    "패치 가능": "Patch available",
    "필수": "Required",
    '기본 프로젝트': 'Default project',
    '현재 파서와 매핑 기준으로 바로 반영 가능한 파일입니다.': 'This file is ready to import with the current parser and mapping.',
    '제품·취약점명': 'Product / vulnerability',
    '자산·호스트명': 'Asset / hostname',
    'IP 주소': 'IP address',
    '스캐너 원본 결과 ID': 'Scanner source finding ID',
    '제품 버전': 'Product version',
    '자산 ID': 'Asset ID',
    '구성요소·플러그인': 'Component / plugin',
    '구성요소 버전': 'Component version',
    'CISA KEV 여부': 'CISA KEV',
    '패치·해결책 존재': 'Patch / remediation available',
    '설명·조치 메모': 'Description / remediation notes',

}
_DYNAMIC_PARTIAL_EN = (
    ('즉시 실행 가능성 반영', 'Immediate exploitability considered'),
    ('패치 사용 가능', 'Patch available'),
    ('데이터 민감도', 'Data sensitivity'),
    ('보완통제 없음', 'No compensating controls'),
    ('서비스 포트', 'Service port'),
    ('자산 중요도', 'Asset criticality'),
    ('해결 방법', 'Remediation'),
)


def format_items(value) -> str:
    try:
        count = int(value)
    except (TypeError, ValueError):
        return f"{value} items"
    return f"{count} item" if count == 1 else f"{count} items"


def language_from_request(request) -> str:
    try:
        value = str(request.cookies.get(UI_LANGUAGE_COOKIE, "ko")).lower()
    except Exception:
        value = "ko"
    return "en" if value == "en" else "ko"

def localized_template(request, name: str) -> str:
    if language_from_request(request) != "en" or name not in LOCALIZED_TEMPLATES:
        return name
    if not name.endswith(".html"):
        return name
    return name[:-5] + ".en.html"

def valid_ui_language(value: str) -> bool:
    return str(value).lower() in SUPPORTED_UI_LANGUAGES

def safe_next_path(value: str) -> str:
    value = str(value or "/")
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    return value

def translate_message(value):
    if value is None:
        return ""
    text = str(value)
    text = _DYNAMIC_EN.get(text, text)
    for ko, en in _DYNAMIC_PARTIAL_EN:
        text = text.replace(ko, en)
    # Translate the paired app-generated service/port shape only.
    # Standalone Korean words remain untouched.
    service_at = text.find("서비스")
    port_at = text.find("포트", service_at + 1) if service_at >= 0 else -1
    if service_at >= 0 and port_at >= 0 and port_at - service_at <= 64:
        text = text[:service_at] + "Service" + text[service_at + len("서비스"):]
        port_at = text.find("포트", service_at + len("Service"))
        if port_at >= 0:
            text = text[:port_at] + "port" + text[port_at + len("포트"):]
    return text
