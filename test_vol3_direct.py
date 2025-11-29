"""
Direct Volatility3 test to understand why treegrid.populate() returns None
"""
import logging
import os
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import modules, driverscan

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_modules(memory_path):
    print(f"\n{'='*60}")
    print(f"Testing: {memory_path}")
    print(f"{'='*60}\n")

    # Create context
    ctx = contexts.Context()
    file_path = os.path.abspath(memory_path)
    file_uri = f"file:///{file_path.replace(os.sep, '/')}"

    ctx.config['automagic.LayerStacker.single_location'] = file_uri

    # Run automagic
    available = automagic.available(ctx)
    automagics = automagic.choose_automagic(available, modules.Modules)

    if not automagics:
        print("ERROR: No automagics found!")
        return

    print("Running automagic...")
    automagic.run(automagics, ctx, modules.Modules, 'plugins.Modules')

    # Find kernel module
    kernel_name = None
    for module_name in ctx.modules:
        module = ctx.modules[module_name]
        if hasattr(module, 'layer_name') and hasattr(module, 'symbol_table_name'):
            kernel_name = module_name
            print(f"Found kernel module: {kernel_name}")
            break

    if not kernel_name:
        print("ERROR: Could not find kernel module")
        return

    # Test Modules plugin
    print("\n--- Testing Modules Plugin ---")
    plugin_config = 'plugins.Modules'
    ctx.config[f'{plugin_config}.kernel'] = kernel_name

    plugin = modules.Modules(context=ctx, config_path=plugin_config)
    treegrid = plugin.run()

    print(f"Treegrid object: {treegrid}")
    print(f"Treegrid type: {type(treegrid)}")

    if treegrid is None:
        print("ERROR: Treegrid is None!")
        return

    print("Calling populate()...")
    populated = treegrid.populate(lambda *args: None)

    print(f"Populated object: {populated}")
    print(f"Populated type: {type(populated)}")

    if populated is None:
        print("ERROR: populate() returned None!")
    else:
        count = 0
        try:
            for row in populated:
                level, values = row
                if len(values) >= 4:
                    print(f"  Module: {values[3]}")
                    count += 1
                    if count >= 10:
                        print(f"  ... (showing first 10)")
                        break
        except Exception as e:
            print(f"ERROR iterating: {e}")

        print(f"Total modules found: {count}")

    # Test DriverScan plugin
    print("\n--- Testing DriverScan Plugin ---")
    plugin_config = 'plugins.DriverScan'
    ctx.config[f'{plugin_config}.kernel'] = kernel_name

    plugin = driverscan.DriverScan(context=ctx, config_path=plugin_config)
    treegrid = plugin.run()

    print(f"Treegrid object: {treegrid}")
    print(f"Treegrid type: {type(treegrid)}")

    if treegrid is None:
        print("ERROR: Treegrid is None!")
        return

    print("Calling populate()...")
    populated = treegrid.populate(lambda *args: None)

    print(f"Populated object: {populated}")
    print(f"Populated type: {type(populated)}")

    if populated is None:
        print("ERROR: populate() returned None!")
    else:
        count = 0
        try:
            for row in populated:
                level, values = row
                if len(values) >= 4:
                    print(f"  Driver: {values[4]}")
                    count += 1
                    if count >= 10:
                        print(f"  ... (showing first 10)")
                        break
        except Exception as e:
            print(f"ERROR iterating: {e}")

        print(f"Total drivers found: {count}")

if __name__ == "__main__":
    # Test both memory dumps
    test_modules("memdump.mem")
    test_modules("vuln.mem")
