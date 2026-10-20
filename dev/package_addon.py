"""Create an installable ZIP using the API versions of the selected Kodi SDK."""

import argparse
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile


KODI_VERSIONS = {
    "Omega": (21, "21.0.0", "21.90.0"),
    "Piers": (22, "21.90.1", "22.90.0"),
}


def prepare_manifest(source, sdk, codename, tag=None):
    root = ET.parse(source / "addon.xml").getroot()
    version = root.attrib["version"]
    if tag and tag not in (version, f"v{version}"):
        raise ValueError(f"Tag {tag!r} must match addon.xml version {version!r} (optional v prefix)")

    major, minimum, maximum = KODI_VERSIONS[codename]
    version_text = (sdk / "version.txt").read_text(encoding="utf-8")
    if not re.search(rf"^VERSION_MAJOR\s+{major}\s*$", version_text, re.MULTILINE):
        raise ValueError(f"Kodi source does not match {codename} / Kodi {major}")

    headers = sdk / "xbmc/addons/kodi-dev-kit/include/kodi/versions.h"
    sdk_versions = headers.read_text(encoding="utf-8")
    requires = root.find("requires")
    if requires is None:
        requires = ET.SubElement(root, "requires")
    dependencies = {
        "kodi.binary.global.main": "ADDON_GLOBAL_VERSION_MAIN",
        "kodi.binary.instance.vfs": "ADDON_INSTANCE_VERSION_VFS",
    }
    for addon, macro in dependencies.items():
        match = re.search(rf'^#define\s+{macro}\s+"([^"]+)"', sdk_versions, re.MULTILINE)
        if not match:
            raise ValueError(f"Missing {macro} in {headers}")
        # Use the SDK's compatible minimum, not its current API version.
        # Piers API 2.0.4 supports 2.0.3; requiring 2.0.4 in XML would hide
        # this compatible binary on Kodi 22 beta systems.
        minimum_match = re.search(
            rf'^#define\s+{macro}_MIN\s+"([^"]+)"', sdk_versions, re.MULTILINE)
        api_version = minimum_match.group(1) if minimum_match else match.group(1)
        if tuple(map(int, api_version.split('.'))) > tuple(map(int, match.group(1).split('.'))):
            raise ValueError(f"{macro}_MIN exceeds {macro} in {headers}")
        dependency = requires.find(f"import[@addon='{addon}']")
        if dependency is None:
            dependency = ET.SubElement(requires, "import", addon=addon)
        dependency.set("version", api_version)

    dependency = requires.find("import[@addon='xbmc.addon']")
    if dependency is None:
        dependency = ET.SubElement(requires, "import", addon="xbmc.addon")
    dependency.set("version", minimum)
    dependency.set("maxversion", maximum)
    ET.indent(root)
    return root


def package_addon(source, sdk, codename, platform, build_dir, output_dir, tag=None):
    root = prepare_manifest(source, sdk, codename, tag)
    addon_id = root.attrib["id"]
    system = platform.split("-", 1)[0]
    library = root.find("extension[@point='kodi.vfs']").get(f"library_{system}")
    if not library:
        raise ValueError(f"Unsupported platform: {platform}")

    # Match only this add-on, never one of the dependency DLLs/shared libraries.
    # CMake adds "lib" on macOS, while Kodi's library_osx name omits it.
    binary_name = f"lib{library}" if system == "osx" else library
    binaries = sorted(build_dir.rglob(binary_name))
    if len(binaries) != 1:
        raise ValueError(f"Expected one {library} in {build_dir}, found {binaries}")
    if not binaries[0].stat().st_size:
        raise ValueError(f"Empty binary: {binaries[0]}")

    output_dir.mkdir(parents=True, exist_ok=True)
    name = f"{addon_id}-{root.attrib['version']}-{codename}-{platform}"
    output = output_dir / f"{name}.zip"
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{addon_id}/addon.xml", ET.tostring(root, encoding="utf-8", xml_declaration=True))
        archive.write(binaries[0], f"{addon_id}/{library}")
        for filename in ("icon.png", "LICENSE.txt"):
            archive.write(source / filename, f"{addon_id}/{filename}")
        for path in sorted((source / "resources").rglob("*")):
            if path.is_file():
                archive.write(path, f"{addon_id}/{path.relative_to(source).as_posix()}")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--kodi-source", type=Path, required=True)
    parser.add_argument("--kodi", choices=KODI_VERSIONS, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--tag")
    args = parser.parse_args()
    output = package_addon(args.source, args.kodi_source, args.kodi, args.platform,
                           args.build_dir, args.output_dir, args.tag)
    print(f"Created {output}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"name={output.stem}\npath={output.as_posix()}\n")


if __name__ == "__main__":
    main()
