import os
import sysconfig

site_packages_dir = sysconfig.get_paths()["purelib"]
linotp_custom_assets_dir = f"{site_packages_dir}/linotp/public/custom"

custom_assets_dir = os.environ["CUSTOM_ASSETS_DIR"]

os.symlink(linotp_custom_assets_dir, custom_assets_dir)
