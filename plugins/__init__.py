# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""iKARMA plugins for Windows driver analysis"""

import os
import sys

# This is necessary to ensure the core plugins are available, whilst still be overridable
parent_module, module_name = ".".join(__name__.split(".")[:-1]), __name__.split(".")[-1]
__path__ = [os.path.join(x, module_name) for x in sys.modules[parent_module].__path__]
