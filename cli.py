from __future__ import annotations
import argparse,csv,json
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from qraf.model import Finding,AssetType,EvidenceLevel
from qraf.cbom_lite.adapters.pem_certs import read_certificates
from qraf.cbom_lite.adapters.vendor_csv import read_vendor_questionnaire
from qraf.cbom_lite.adapters.tls_scan import findings_from_sslyze_json
from qraf.cbom_lite.adapters.ssh_scan import findings_from_ssh_audit_json
from qraf.cbom_lite.cyclonedx import to_cyclonedx
from qraf.qesm.score import load_config,load_assets,score_assets
from qraf.qesm.sensitivity import horizon_sensitivity,weight_sensitivity

def build_parser()->argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog="qraf",description="QRAF toolkit")
    sub=parser.add_subparsers(dest="command",required=True)
    for name in ("certs","tls","ssh","vendors"):
        p=sub.add_parser(name);p.add_argument("path");p.add_argument("-o","--output",required=True)
    p=sub.add_parser("cbom");p.add_argument("inputs",nargs="+");p.add_argument("-o","--output",required=True)
    p=sub.add_parser("qesm");p.add_argument("assets");p.add_argument("-c","--config",required=True);p.add_argument("-o","--output",required=True);p.add_argument("--horizon",type=float);p.add_argument("--sensitivity")
    return parser

def main(argv:list[str]|None=None)->int:
    a=build_parser().parse_args(argv)
    if a.command in ("certs","tls","ssh","vendors"):
        fn={"certs":read_certificates,"tls":findings_from_sslyze_json,"ssh":findings_from_ssh_audit_json,"vendors":read_vendor_questionnaire}[a.command]
        data=[asdict(x) for x in fn(a.path)]
        Path(a.output).write_text(json.dumps(data,indent=2,default=lambda v:v.value if isinstance(v,Enum) else str(v))+"\n")
    elif a.command=="cbom":
        findings=[]
        for file in a.inputs:
            for item in json.loads(Path(file).read_text()):
                item["asset_type"]=AssetType(item["asset_type"]);item["evidence_level"]=EvidenceLevel(item["evidence_level"])
                findings.append(Finding(**item))
        Path(a.output).write_text(json.dumps(to_cyclonedx(findings),indent=2)+"\n")
    else:
        config=load_config(a.config);assets=load_assets(a.assets);rows=score_assets(assets,config,a.horizon)
        with open(a.output,"w",newline="") as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else list(assets[0]) if assets else [])
            writer.writeheader();writer.writerows(rows)
        if a.sensitivity:Path(a.sensitivity).write_text(json.dumps({"horizon":horizon_sensitivity(assets,config),"weights":weight_sensitivity(assets,config)},indent=2)+"\n")
    return 0

if __name__=="__main__":raise SystemExit(main())
