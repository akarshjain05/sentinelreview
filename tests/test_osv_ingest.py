import io
import json
import zipfile
import httpx
import pytest
import respx

from app.knowledge.osv_ingest import (
    OSVIngestError,
    advisories_to_knowledge_documents,
    fetch_advisories,
)

_OSV_RECORD_1 = {
    "id": "OSV-2023-111",
    "summary": "Buffer overflow in package X",
    "details": "When processing long strings, a buffer overflow occurs.",
    "aliases": ["CVE-2023-111", "CWE-120"],
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "references": [
        {"type": "ADVISORY", "url": "https://example.com/advisory"}
    ]
}

_OSV_RECORD_2 = {
    "id": "PYSEC-2023-222",
    "details": "A vulnerability with database_specific cwe.",
    "database_specific": {
        "cwes": [{"cweId": "CWE-79"}],
        "severity": "MODERATE"
    }
}

def create_mock_zip(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, record in enumerate(records):
            z.writestr(f"{record['id']}.json", json.dumps(record))
    return buf.getvalue()

@respx.mock
def test_osv_fetch_advisories_parses_real_response_shape():
    zip_data = create_mock_zip([_OSV_RECORD_1, _OSV_RECORD_2])
    respx.get("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip").mock(
        return_value=httpx.Response(200, content=zip_data)
    )
    
    advisories = fetch_advisories(ecosystem="PyPI")
    assert len(advisories) == 2
    
    # Sort them by id to predictably assert
    advisories.sort(key=lambda a: a.osv_id)
    
    a1 = advisories[0] # OSV-2023-111
    assert a1.osv_id == "OSV-2023-111"
    assert a1.cwe_ids == ["CWE-120"]
    assert a1.severity == "high" # default due to having CVSS
    assert a1.url == "https://example.com/advisory"
    
    a2 = advisories[1] # PYSEC-2023-222
    assert a2.osv_id == "PYSEC-2023-222"
    assert a2.cwe_ids == ["CWE-79"]
    assert a2.severity == "moderate"
    assert a2.url == "https://osv.dev/vulnerability/PYSEC-2023-222"

@respx.mock
def test_osv_fetch_advisories_handles_404():
    respx.get("https://osv-vulnerabilities.storage.googleapis.com/UnknownEcosystem/all.zip").mock(
        return_value=httpx.Response(404)
    )
    with pytest.raises(OSVIngestError, match="Ecosystem UnknownEcosystem not found"):
        fetch_advisories(ecosystem="UnknownEcosystem")

@respx.mock
def test_osv_advisories_to_knowledge_documents_shape():
    zip_data = create_mock_zip([_OSV_RECORD_1])
    respx.get("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip").mock(
        return_value=httpx.Response(200, content=zip_data)
    )
    
    advisories = fetch_advisories(ecosystem="PyPI")
    docs = advisories_to_knowledge_documents(advisories)
    
    assert docs[0]["source"] == "osv"
    assert docs[0]["external_id"] == "OSV-2023-111"
    assert docs[0]["cwe_ids"] == "CWE-120"
