from __future__ import annotations
from typing import Any
from qraf.qesm.score import score_assets

def horizon_sensitivity(assets:list[dict[str,Any]],config:dict[str,Any])->dict[str,Any]:
    default=config["default_horizon_years"]
    horizons=list(dict.fromkeys([*config["sensitivity_horizons"],default]))
    by_h={h:{r["asset_id"]:r["tier"] for r in score_assets(assets,config,h)} for h in horizons}
    return {"tiers":{a["asset_id"]:{h:by_h[h][a["asset_id"]] for h in horizons} for a in assets},"changes_vs_default":{h:sum(by_h[h][a["asset_id"]]!=by_h[default][a["asset_id"]] for a in assets) for h in horizons}}

def weight_sensitivity(assets:list[dict[str,Any]],config:dict[str,Any],delta:float=0.05)->list[dict[str,Any]]:
    base={r["asset_id"]:r["tier"] for r in score_assets(assets,config)}
    result=[]
    for name in config["weights"]:
        for direction in (-1,1):
            weights=dict(config["weights"]);weights[name]+=direction*delta
            if any(v<0 for v in weights.values()):raise ValueError("negative sensitivity weight")
            total=sum(weights.values());weights={k:v/total for k,v in weights.items()}
            modified={**config,"weights":weights}
            changed=sum(r["tier"]!=base[r["asset_id"]] for r in score_assets(assets,modified))
            result.append({"weight":name,"direction":direction,"weights":weights,"tier_changes":changed})
    return result
