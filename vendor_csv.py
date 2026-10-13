from __future__ import annotations
import csv
from pathlib import Path
from qraf.cbom_lite.classify import normalize_algorithm
from qraf.model import Finding,AssetType,EvidenceLevel

def read_vendor_questionnaire(path:str|Path)->list[Finding]:
    with open(path,encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        required={"vendor","service","connection","algorithm","parameter","protocol","pqc_roadmap_date","cisa_product_category","fips_140_3_module"}
        missing=required-set(reader.fieldnames or [])
        if missing:raise ValueError("missing columns: "+", ".join(sorted(missing)))
        out=[]
        for i,r in enumerate(reader,1):
            family,embedded=normalize_algorithm(r["algorithm"])
            out.append(Finding(asset_id=f"vendor-{i}",location=f"{r['vendor']} / {r['service']}",source="vendor_csv",evidence_level=EvidenceLevel.VENDOR_ATTESTED,asset_type=AssetType.ALGORITHM,algorithm=family,parameter=r["parameter"] or embedded,protocol=r["protocol"],vendor=r["vendor"],extra={k:r[k] for k in ("connection","pqc_roadmap_date","cisa_product_category","fips_140_3_module")}))
    return out
