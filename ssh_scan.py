from __future__ import annotations
import json
from pathlib import Path
from qraf.model import Finding,AssetType,EvidenceLevel
from qraf.cbom_lite.classify import normalize_algorithm

def findings_from_ssh_audit_json(path:str|Path)->list[Finding]:
    doc=json.loads(Path(path).read_text())
    if not isinstance(doc,dict):raise ValueError("ssh-audit JSON must be an object")
    target=doc.get("target",{})
    location=f"{target.get('host','lab-ssh')}:{target.get('port',22)}" if isinstance(target,dict) else str(target)
    out=[]
    for field,primitive in (("kex","key-agree"),("key","signature")):
        entries=doc.get(field,[])
        if isinstance(entries,dict):entries=list(entries)
        for i,entry in enumerate(entries):
            name=entry if isinstance(entry,str) else entry.get("algorithm",entry.get("name","")) if isinstance(entry,dict) else ""
            if not name:continue
            family,param=normalize_algorithm(name)
            out.append(Finding(asset_id=f"ssh-{field}-{i+1}",location=location,source="ssh_scan",evidence_level=EvidenceLevel.OBSERVED,asset_type=AssetType.ALGORITHM,algorithm=family,parameter=param,primitive=primitive,protocol="SSH",extra={"raw_name":name}))
    return out
