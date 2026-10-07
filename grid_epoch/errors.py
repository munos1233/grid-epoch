class ProtocolError(Exception):
    """报文或状态不合法。"""


class AuthFailed(ProtocolError):
    """认证标签校验失败。"""


class EpochRejected(ProtocolError):
    """纪元签名、顺序或重放检查未通过。"""


class TerminalRevoked(ProtocolError):
    """终端已从当前纪元的覆盖集中剔除。"""
