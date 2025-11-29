import logging
import sys
import os
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import info

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def run_info(memory_path):
    print(f"Testing Volatility3 on: {memory_path}")
    
    ctx = contexts.Context()
    file_path = os.path.abspath(memory_path)
    file_uri = f"file:///{file_path.replace(os.sep, '/')}"
    
    ctx.config['automagic.LayerStacker.single_location'] = file_uri
    
    available = automagic.available(ctx)
    automagics = automagic.choose_automagic(available, info.Info)
    
    if not automagics:
        print("No automagics found!")
        return

    print("Running automagics...")
    automagic.run(automagics, ctx, info.Info, 'plugins.Info')
    
    print("Running Info plugin...")
    plugin = info.Info(ctx, 'plugins.Info')
    tree = plugin.run()
    
    for row in tree.populate(lambda *args: None):
        print(row)

if __name__ == "__main__":
    run_info("memdump.mem")
