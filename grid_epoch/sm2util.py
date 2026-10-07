"""SM2/SM3 签名。用户标识使用 GM/T 0009 默认值 1234567812345678。"""

from __future__ import annotations

import secrets

from gmssl import sm2


class SM2Signer:
    def __init__(self) -> None:
        n = int(sm2.default_ecc_table["n"], 16)
        d = secrets.randbelow(n - 1) + 1
        sk = f"{d:064x}"
        helper = sm2.CryptSM2(public_key="0" * 128, private_key=sk)
        pk = helper._kg(d, helper.ecc_table["g"])
        self.public_key = pk
        self._crypt = sm2.CryptSM2(public_key=pk, private_key=sk)

    def sign(self, data: bytes) -> bytes:
        for _ in range(8):
            sig = self._crypt.sign_with_sm3(data)
            if sig:
                return bytes.fromhex(sig)
        raise RuntimeError("SM2 签名失败")

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            return bool(self._crypt.verify_with_sm3(signature.hex(), data))
        except Exception:
            return False


def verifier(public_key: str):
    crypt = sm2.CryptSM2(public_key=public_key, private_key="0" * 64)

    def verify(data: bytes, signature: bytes) -> bool:
        try:
            return bool(crypt.verify_with_sm3(signature.hex(), data))
        except Exception:
            return False

    return verify
