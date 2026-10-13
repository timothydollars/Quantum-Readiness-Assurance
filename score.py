from __future__ import annotations
import csv, math
from pathlib import Path
from typing import Any
import yaml

WEIGHT_KEYS=("timeline","exposure","criticality","dependency")
NUMERIC=("x_shelf_life_years","y_migration_years")
INTEGER=("e_exposure","c_criticality","d_dependency")

def load_config(path: str|Path)->dict[str,Any]:
    with open(path,encoding="utf-8") as f: cfg=yaml.safe_load(f)
    w=cfg["weights"]
    if set(w)!=set(WEIGHT_KEYS) or not all(isinstance(w[k],(int,float)) and math.isfinite(w[k]) and w[k]>=0 for k in WEIGHT_KEYS) or abs(sum(w.values())-1)>1e-9:
        raise ValueError("weights must be nonnegative and sum to one")
    return cfg

def load_assets(path: str|Path)->list[dict[str,Any]]:
    out=[]; seen=set()
    with open(path,newline="",encoding="utf-8-sig") as f:
        reader=csv.DictReader(f)
        required={"asset_id","description",*NUMERIC,*INTEGER}
        missing=required-set(reader.fieldnames or [])
        if missing: raise ValueError("missing columns: "+", ".join(sorted(missing)))
        for row in reader:
            asset=row.get("asset_id") or "<blank>"
            if asset in seen: raise ValueError(f"{asset}: duplicate asset_id")
            seen.add(asset)
            for k in NUMERIC:
                try:
                    v=float(row[k]); assert math.isfinite(v) and v>=0
                    row[k]=v
                except (ValueError,TypeError,AssertionError): raise ValueError(f"{asset}: invalid {k}") from None
            for k in INTEGER:
                try:
                    v=float(row[k]); assert v.is_integer() and 1<=v<=5
                    row[k]=int(v)
                except (ValueError,TypeError,AssertionError): raise ValueError(f"{asset}: invalid {k}") from None
            out.append(row)
    return out

def timeline_gap(x:float,y:float,z:float)->float:return x+y-z

def timeline_score(gap:float)->int:
    return 5 if gap>=0 else 4 if gap>=-2 else 3 if gap>=-4 else 2 if gap>=-6 else 1

def priority(t:int,e:int,c:int,d:int,weights:dict[str,float])->float:
    return round(t*weights["timeline"]+e*weights["exposure"]+c*weights["criticality"]+d*weights["dependency"],2)

def tier(p:float,thresholds:dict[str,float])->int:
    return 1 if p>=thresholds["tier1_min"] else 2 if p>=thresholds["tier2_min"] else 3

def score_assets(assets:list[dict[str,Any]],config:dict[str,Any],horizon:float|None=None)->list[dict[str,Any]]:
    z=config["default_horizon_years"] if horizon is None else horizon
    result=[]
    for a in assets:
        row=dict(a)
        gap=timeline_gap(a["x_shelf_life_years"],a["y_migration_years"],z)
        t=timeline_score(gap)
        pr=priority(t,a["e_exposure"],a["c_criticality"],a["d_dependency"],config["weights"])
        row.update({"gap":gap,"T":t,"P":pr,"tier":tier(pr,config["tier_thresholds"])})
        result.append(row)
    return sorted(result,key=lambda r:(-r["P"],r["asset_id"]))
