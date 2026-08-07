"""Bounded XML parsing helpers shared by scanner adapters."""
from __future__ import annotations

import io
import re
from typing import Any
from xml.etree import ElementTree as ET

from app.core.settings import MAX_IMPORT_UPLOAD_BYTES
from app.services.finding_import_common import _extract_cves

_XML_BLOCKED_RE = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
XML_MAX_DEPTH = 128
XML_MAX_NODES = 250_000
XML_MAX_TEXT_CHARS = 16 * 1024 * 1024


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


def _children_by_name(element: ET.Element, name: str) -> list[ET.Element]:
    expected = name.casefold()
    return [child for child in element.iter() if _local_name(child.tag) == expected]


def _first_text(element: ET.Element | None, *names: str) -> str:
    if element is None:
        return ""
    expected = {name.casefold() for name in names}
    for child in element.iter():
        if _local_name(child.tag) in expected and child.text:
            text = child.text.strip()
            if text:
                return text
    return ""


def _safe_xml_document(content: bytes) -> tuple[ET.Element, dict[str, int]]:
    if len(content) > MAX_IMPORT_UPLOAD_BYTES:
        raise ValueError(
            f"XML 가져오기 파일은 최대 {MAX_IMPORT_UPLOAD_BYTES // (1024 * 1024)}MB입니다."
        )
    if _XML_BLOCKED_RE.search(content):
        raise ValueError("DOCTYPE 또는 ENTITY가 포함된 XML은 지원하지 않습니다.")
    depth = max_depth = node_count = text_chars = 0
    root: ET.Element | None = None
    try:
        for event, element in ET.iterparse(io.BytesIO(content), events=("start", "end")):
            if event == "start":
                if root is None:
                    root = element
                depth += 1
                max_depth = max(max_depth, depth)
                node_count += 1
                if max_depth > XML_MAX_DEPTH:
                    raise ValueError(f"XML 중첩 깊이는 최대 {XML_MAX_DEPTH}단계입니다.")
                if node_count > XML_MAX_NODES:
                    raise ValueError(f"XML 요소 수는 최대 {XML_MAX_NODES:,}개입니다.")
                if len(element.attrib) > 256:
                    raise ValueError("XML 요소의 속성 수가 비정상적으로 많습니다.")
            else:
                text_chars += len(element.text or "") + len(element.tail or "")
                if text_chars > XML_MAX_TEXT_CHARS:
                    raise ValueError("XML 텍스트 총량이 허용 범위를 초과했습니다.")
                depth -= 1
    except ET.ParseError as exc:
        raise ValueError(f"XML 형식 오류: {exc}") from exc
    if root is None:
        raise ValueError("XML 문서에 루트 요소가 없습니다.")
    return root, {
        "xml_nodes": node_count,
        "xml_max_depth": max_depth,
        "xml_text_chars": text_chars,
    }


def _safe_xml_root(content: bytes) -> ET.Element:
    root, _ = _safe_xml_document(content)
    return root


def _reference_cves(element: ET.Element | None) -> list[str]:
    if element is None:
        return []
    values: list[str] = []
    for child in element.iter():
        name = _local_name(child.tag)
        if name == "cve":
            values.append(child.text or "")
        elif name == "ref":
            ref_type = str(child.attrib.get("type") or "").strip().casefold()
            ref_id = str(child.attrib.get("id") or child.attrib.get("name") or "").strip()
            if ref_type in {"", "cve", "cve_id", "cve-id"} or "CVE-" in ref_id.upper():
                values.extend((ref_id, child.text or ""))
    return _extract_cves(*values)


__all__ = [
    "XML_MAX_DEPTH",
    "XML_MAX_NODES",
    "XML_MAX_TEXT_CHARS",
    "_children_by_name",
    "_first_text",
    "_local_name",
    "_reference_cves",
    "_safe_xml_document",
    "_safe_xml_root",
]
