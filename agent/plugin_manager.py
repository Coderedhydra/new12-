from .plugins.info_disclosure import InfoDisclosurePlugin
from .plugins.reflection_probe import ReflectionProbePlugin
from .plugins.security_headers import SecurityHeadersPlugin


def build_plugins() -> list:
    return [
        SecurityHeadersPlugin(),
        ReflectionProbePlugin(),
        InfoDisclosurePlugin(),
    ]
