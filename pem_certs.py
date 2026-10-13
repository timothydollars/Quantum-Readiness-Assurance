from __future__ import annotations
import re,warnings,subprocess
from datetime import timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed25519,ed448,dsa,dh
from qraf.model import Finding,AssetType,EvidenceLevel

def read_certificates(path:str|Path)->list[Finding]:
    p=Path(path)
    paths=sorted([f for f in p.iterdir() if f.suffix.lower() in (".pem",".crt")]) if p.is_dir() else [p]
    findings=[]
    for file in paths:
        try:
            data=file.read_bytes()
            blocks=re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",data,re.S)
            if not blocks:raise ValueError("no PEM certificate")
            for idx,block in enumerate(blocks):
                cert=x509.load_pem_x509_certificate(block);key=cert.public_key()
                if isinstance(key,rsa.RSAPublicKey):family,param="RSA",str(key.key_size)
                elif isinstance(key,ec.EllipticCurvePublicKey):
                    family="ECDSA";param={"secp256r1":"P-256","secp384r1":"P-384","secp521r1":"P-521"}.get(key.curve.name,key.curve.name)
                elif isinstance(key,ed25519.Ed25519PublicKey):family,param="Ed25519",""
                elif isinstance(key,ed448.Ed448PublicKey):family,param="Ed448",""
                elif isinstance(key,dsa.DSAPublicKey):family,param="DSA",str(key.key_size)
                elif isinstance(key,dh.DHPublicKey):family,param="DH",str(key.key_size)
                else:family,param=type(key).__name__,""
                def utc(dt):return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
                findings.append(Finding(asset_id=f"cert-{file.stem}-{idx+1}",location=str(file),source="pem_file",evidence_level=EvidenceLevel.OBSERVED,asset_type=AssetType.CERTIFICATE,algorithm=family,parameter=param,primitive="signature",extra={"subject":cert.subject.rfc4514_string(),"issuer":cert.issuer.rfc4514_string(),"serial":str(cert.serial_number),"not_before":utc(cert.not_valid_before_utc),"not_after":utc(cert.not_valid_after_utc),"signature_algorithm":cert.signature_algorithm_oid.dotted_string}))
        except (OSError,ValueError,TypeError) as exc:
            # cryptography versions may not yet support ML-DSA public-key OIDs.
            # OpenSSL can inspect the public certificate without exposing a private key.
            if "Unknown key type" in str(exc):
                try:
                    result=subprocess.run(["openssl","x509","-in",str(file),"-noout","-subject","-issuer","-serial","-startdate","-enddate","-text"],capture_output=True,text=True,check=True).stdout
                    if "ML-DSA-65" not in result and "2.16.840.1.101.3.4.3.18" not in result:
                        raise ValueError("unsupported public key type")
                    def value(prefix):
                        m=re.search(r"^"+prefix+r"=(.*)$",result,re.M)
                        return m.group(1).strip() if m else ""
                    from datetime import datetime
                    def date(prefix):
                        v=value(prefix)
                        return datetime.strptime(v,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z") if v else ""
                    findings.append(Finding(asset_id=f"cert-{file.stem}-1",location=str(file),source="pem_file",evidence_level=EvidenceLevel.OBSERVED,asset_type=AssetType.CERTIFICATE,algorithm="ML-DSA",parameter="65",primitive="signature",extra={"subject":value("subject"),"issuer":value("issuer"),"serial":value("serial"),"not_before":date("notBefore"),"not_after":date("notAfter"),"signature_algorithm":"ML-DSA-65"}))
                    continue
                except (OSError,ValueError,subprocess.CalledProcessError) as other:
                    warnings.warn(f"Skipping invalid certificate {file}: {other}")
                    continue
            warnings.warn(f"Skipping invalid certificate {file}: {exc}")
    return findings
