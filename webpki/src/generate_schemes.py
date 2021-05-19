import subprocess
import os

from typing import Iterable, Any, Tuple

def signal_last(it: Iterable[Any]) -> Iterable[Tuple[bool, Any]]:
    iterable = iter(it)
    ret_var = next(iterable)
    for val in iterable:
        yield False, ret_var
        ret_var = val
    yield True, ret_var


# sigs
from algorithms import signs, kems, get_oid

for alg, oqsalg in signs:
    input_str = f"OBJECT_IDENTIFIER {{ {get_oid(alg)} }}\n"

    subprocess.run(
        ["../../mk-cert/ascii2der", "-o", f"data/alg-{alg}.der"],
        input=input_str.encode(),
        check=True
    )
    subprocess.run(["git", "add", f"data/alg-{alg}.der"], check=True)


with open('generated/oqs_sigschemes.rs', 'w') as fh:
    for alg, oqsalg in signs:
        if alg == "xmss":
            continue
        fh.write(f"""
const {alg.upper()}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-{alg}.der")),
}};

/// {alg} signatures
pub static {alg.upper()}: SignatureAlgorithm = SignatureAlgorithm {{
    public_key_alg_id: {alg.upper()}_ID,
    signature_alg_id: {alg.upper()}_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::{oqsalg}),
}};
""")

with open('generated/oqs_sigschemes_use.rs', 'w') as fh:
    for alg, oqsalg in signs:
        fh.write(f"pub use signed_data::{alg.upper()};\n")

## KEMs
for alg, oqsalg in kems:
    input_str = f"OBJECT_IDENTIFIER {{ {get_oid(alg)} }}\n"

    subprocess.run(
        ["../../mk-cert/ascii2der", "-o", f"data/alg-{alg}.der"],
        input=input_str.encode(),
        check=True,
    )
    subprocess.run(["git", "add", f"data/alg-{alg}.der"], check=True)

with open('generated/oqs_kems.rs', 'w') as fh:
    for alg, oqsalg in kems:
        fh.write(f"""
const {alg.upper()}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-{alg}.der")),
}};

/// {alg} KEM
pub static {alg.upper()}: KemAlgorithm = KemAlgorithm {{
    public_key_alg_id: {alg.upper()}_ID,
    kem: oqs::kem::Algorithm::{oqsalg},
}};
""")

with open('generated/get_kem.rs', 'w') as fh:
    for last, (alg, oqsalg) in signal_last(kems):
        fh.write(f"""
        if check_key_id(&{alg.upper()}, algorithm_id) {{
            return Ok(&{alg.upper()});
        }} {'' if last else 'else '}
""")
