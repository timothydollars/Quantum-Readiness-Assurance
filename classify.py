from __future__ import annotations
import re
from qraf.model import Category, Classification

def normalize_algorithm(name: str) -> tuple[str,str]:
    raw=name.strip(); compact=re.sub(r"[-_\s]", "", raw).upper()
    if "MLKEM" in compact and not compact.startswith("MLKEM"):
        return raw,""
    for token,family in (("MLKEM","ML-KEM"),("MLDSA","ML-DSA")):
        if compact.startswith(token):
            return family,compact[len(token):]
    if compact.startswith("SLHDSA"):
        tail=re.sub(r"(?i)^SLH[-_]?DSA[-_]?", "", raw)
        return "SLH-DSA",tail
    if compact in ("RSA","RSAENCRYPTION"):
        return "RSA",""
    return raw,""

def classify(family: str, parameter: str="") -> Classification:
    f=family.upper().replace("_", "-"); p=parameter.upper()
    classical={"RSA","DSA","DH","ECDSA","ECDH","EDDSA","ED25519","ED448","X25519","X448"}
    if f in classical:
        weak=f in {"RSA","DSA","DH"} and parameter.isdigit() and int(parameter)<2048
        return Classification(Category.VULNERABLE,0,weak)
    if "MLKEM" in f.replace("-", "") and not f.replace("-", "").startswith("MLKEM"):
        m=re.search(r"MLKEM(512|768|1024)",f.replace("-", ""))
        return Classification(Category.HYBRID,{"512":1,"768":3,"1024":5}.get(m.group(1)) if m else None)
    levels={"ML-KEM":{"512":1,"768":3,"1024":5},"ML-DSA":{"44":2,"65":3,"87":5}}
    if f in levels:
        return Classification(Category.RESISTANT,levels[f].get(p))
    if f=="SLH-DSA":
        m=re.search(r"(128|192|256)",p)
        return Classification(Category.RESISTANT,{"128":1,"192":3,"256":5}.get(m.group(1)) if m else None)
    if f in {"AES","CHACHA20","SHA-256","SHA-384","SHA-512"} or f.startswith("SHA3-"):
        if f=="AES" and p=="128":return Classification(Category.SYMMETRIC_REVIEW,None)
        return Classification(Category.SYMMETRIC_OK,None)
    if f in {"3DES","RC4","MD5","SHA-1"}:
        return Classification(Category.SYMMETRIC_REVIEW,None,True)
    return Classification(Category.UNKNOWN,None)
