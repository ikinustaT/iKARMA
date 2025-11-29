"""
iKARMA Volatility3 Integration Module

Provides Volatility3 plugin and bridge for DRIVER_OBJECT enumeration.
"""

from ikarma.volatility3.vol3_plugin import (
    HAS_VOLATILITY,
    VolatilityBridge,
    DriverObjectInfo,
    is_volatility_available,
    get_volatility_version,
)

__all__ = [
    'HAS_VOLATILITY',
    'VolatilityBridge',
    'DriverObjectInfo',
    'is_volatility_available',
    'get_volatility_version',
]
