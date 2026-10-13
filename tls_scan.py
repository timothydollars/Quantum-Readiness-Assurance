from __future__ import annotations
import json,re
from pathlib import Path
from qraf.model import Finding,AssetType,EvidenceLevel
from qraf.cbom_lite.classify import normalize_algorithm

def findings_from_sslyze_json(path:str|Path)->list[Finding]:
    doc=json.loads(Path(path).read_text())
    servers=doc.get("server_scan_results",[]) if isinstance(doc,dict) else []
    if not isinstance(servers,list):raise ValueError("invalid sslyze results")
    out=[]
    for si,server in enumerate(servers):
        loc=server.get("server_location",{});host=loc.get("hostname",f"lab-{si}");port=loc.get("port",443)
        location=f"{host}:{port}";commands=server.get("scan_result",{}) or {}
        for name,detail in commands.items():
            if not name.startswith("tls_") or not name.endswith("_cipher_suites") or not isinstance(detail,dict):continue
            result=detail.get("result") or {}
            accepted=result.get("accepted_cipher_suites",[]) or []
            if not accepted:continue
            version=name.removeprefix("tls_").removesuffix("_cipher_suites").replace("_", ".")
            out.append(Finding(asset_id=f"tls-{si}-{version}",location=location,source="tls_scan",evidence_level=EvidenceLevel.OBSERVED,asset_type=AssetType.PROTOCOL,algorithm="TLS",protocol="TLS "+version,extra={"version":version}))
            seen=set()
            for item in accepted:
                group=item.get("ephemeral_key",{}) or {}
                raw=group.get("curve_name") or group.get("group_name") or item.get("key_exchange_group")
                if not raw or raw in seen:continue
                seen.add(raw);family,param=normalize_algorithm(raw)
                out.append(Finding(asset_id=f"tls-{si}-{version}-group-{len(seen)}",location=location,source="tls_scan",evidence_level=EvidenceLevel.OBSERVED,asset_type=AssetType.ALGORITHM,algorithm=family,parameter=param,primitive="kem" if "MLKEM" in raw.upper().replace("-","") else "key-agree",protocol="TLS "+version,extra={"raw_name":raw}))
    return out
