"""
Test the fix for Volatility3 enumeration
"""
import logging
import os
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import modules, driverscan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_fix(memory_path):
    print(f"\n{'='*60}")
    print(f"Testing FIX on: {memory_path}")
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

    # Test Modules plugin with direct _generator() access
    print("\n--- Testing Modules Plugin with _generator() ---")
    plugin_config = 'plugins.Modules'
    ctx.config[f'{plugin_config}.kernel'] = kernel_name

    plugin = modules.Modules(context=ctx, config_path=plugin_config)

    module_count = 0
    driver_count = 0
    try:
        for level, values in plugin._generator():
            if len(values) >= 4:
                name = str(values[3]) if values[3] else ''
                module_count += 1
                if name.lower().endswith('.sys'):
                    driver_count += 1
                    if driver_count <= 10:
                        print(f"  Driver: {name}")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

    print(f"\nTotal modules: {module_count}")
    print(f"Total .sys drivers: {driver_count}")

    # Test DriverScan plugin with direct _generator() access
    print("\n--- Testing DriverScan Plugin with _generator() ---")
    plugin_config = 'plugins.DriverScan'
    ctx.config[f'{plugin_config}.kernel'] = kernel_name

    plugin = driverscan.DriverScan(context=ctx, config_path=plugin_config)

    driver_obj_count = 0
    try:
        for level, values in plugin._generator():
            if len(values) >= 5:
                driver_name = str(values[4]) if values[4] else ''
                driver_obj_count += 1
                if driver_obj_count <= 10:
                    print(f"  Driver: {driver_name}")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

    print(f"\nTotal driver objects: {driver_obj_count}")

if __name__ == "__main__":
    # Test both memory dumps
    test_fix("memdump.mem")
    test_fix("vuln.mem")
