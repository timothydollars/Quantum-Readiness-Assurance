from __future__ import annotations
from datetime import datetime,timezone
from typing import Any
from uuid import uuid4
from qraf.model import Finding,AssetType
from qraf.cbom_lite.classify import classify

PRIMITIVES={"signature","kem","key-agree","pke","hash","mac","block-cipher","stream-cipher","other"}

def to_cyclonedx(findings:list[Finding],tool_version:str="0.1.0")->dict[str,Any]:
    refs=set();components=[];dependencies=[]
    def add(c):
        if c["bom-ref"] in refs:raise ValueError("duplicate bom-ref: "+c["bom-ref"])
        refs.add(c["bom-ref"]);components.append(c)
    for f in findings:
        cls=classify(f.algorithm,f.parameter)
        properties={"qraf:evidenceLevel":f.evidence_level.value,"qraf:source":f.source,"qraf:location":f.location,"qraf:category":cls.category.value,"qraf:classicalWeak":str(cls.classical_weak).lower()}
        if f.owner:properties["qraf:owner"]=f.owner
        if f.vendor:properties["qraf:vendor"]=f.vendor
        if f.data_classes:properties["qraf:dataClasses"]=", ".join(f.data_classes)
        def base(ref,name,kind):
            return {"type":"cryptographic-asset","bom-ref":ref,"name":name,"cryptoProperties":{"assetType":kind},"properties":[{"name":k,"value":v} for k,v in properties.items()]}
        def algorithm(ref):
            c=base(ref,f.algorithm+("-"+f.parameter if f.parameter else ""),"algorithm")
            a={}
            if f.primitive in PRIMITIVES:a["primitive"]=f.primitive
            if f.parameter:a["parameterSetIdentifier"]=f.parameter
            if cls.nist_quantum_level is not None:a["nistQuantumSecurityLevel"]=cls.nist_quantum_level
            c["cryptoProperties"]["algorithmProperties"]=a
            return c
        if f.asset_type==AssetType.CERTIFICATE:
            c=base(f.asset_id,f.extra.get("subject") or f.asset_id,"certificate")
            cp={"certificateFormat":"X.509"}
            for source,target in (("subject","subjectName"),("issuer","issuerName"),("not_before","notValidBefore"),("not_after","notValidAfter")):
                if f.extra.get(source):cp[target]=f.extra[source]
            c["cryptoProperties"]["certificateProperties"]=cp
            add(c);keyref=f.asset_id+":key";add(algorithm(keyref));dependencies.append({"ref":f.asset_id,"dependsOn":[keyref]})
        elif f.asset_type==AssetType.ALGORITHM:add(algorithm(f.asset_id))
        elif f.asset_type==AssetType.PROTOCOL:
            c=base(f.asset_id,f.protocol or f.algorithm,"protocol")
            proto=(f.protocol or f.algorithm).lower()
            pr={"type":"ssh" if "ssh" in proto else "tls" if "tls" in proto else "other"}
            version=f.extra.get("version")
            if not version and f.protocol:
                import re
                m=re.search(r"(\d+(?:\.\d+)*)",f.protocol)
                if m:version=m.group(1)
            if version:pr["version"]=version
            c["cryptoProperties"]["protocolProperties"]=pr
            add(c)
        else:add(base(f.asset_id,f.algorithm or f.asset_id,f.asset_type.value))
    return {"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:"+str(uuid4()),"version":1,"metadata":{"timestamp":datetime.now(timezone.utc).isoformat(),"tools":{"components":[{"type":"application","name":"CBOM-Lite","version":tool_version}]}},"components":components,"dependencies":dependencies}
