from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

from package_addon import package_addon, prepare_manifest


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = Path(__file__).resolve().parents[1]
        self.build = self.base / 'build'
        self.build.mkdir()
        (self.build / 'libvfs.stream.fast.so').write_bytes(b'test binary')

    def package(self, codename='Omega', tag=None, platform='linux-armv7'):
        sdk = self.base / codename
        sdk.mkdir(exist_ok=True)
        major = 21 if codename == 'Omega' else 22
        (sdk / 'version.txt').write_text(f'VERSION_MAJOR {major}\n')
        headers = sdk / 'xbmc/addons/kodi-dev-kit/include/kodi/versions.h'
        headers.parent.mkdir(parents=True, exist_ok=True)
        main = '2.0.2' if codename == 'Omega' else '2.0.4'
        minimum = '2.0.2' if codename == 'Omega' else '2.0.3'
        headers.write_text(f'#define ADDON_GLOBAL_VERSION_MAIN "{main}"\n'
                           f'#define ADDON_GLOBAL_VERSION_MAIN_MIN "{minimum}"\n'
                           '#define ADDON_INSTANCE_VERSION_VFS "3.0.1"\n'
                           '#define ADDON_INSTANCE_VERSION_VFS_MIN "3.0.1"\n', encoding='utf-8')
        return package_addon(self.source, sdk, codename, platform, self.build,
                             self.base / 'dist', tag)

    def test_dual_packages_have_own_sdk_requirements_and_installable_layout(self):
        version = ET.parse(self.source / 'addon.xml').getroot().get('version')
        for codename, main in (('Omega', '2.0.2'), ('Piers', '2.0.3')):
            with self.subTest(kodi=codename):
                package = self.package(codename, f'v{version}')
                self.assertEqual(package.name, f'vfs.stream.fast-{version}-{codename}-linux-armv7.zip')
                with zipfile.ZipFile(package) as archive:
                    self.assertIsNone(archive.testzip())
                    self.assertTrue(all(n.startswith('vfs.stream.fast/') for n in archive.namelist()))
                    self.assertIn('vfs.stream.fast/LICENSE.txt', archive.namelist())
                    self.assertIn('vfs.stream.fast/resources/settings.xml', archive.namelist())
                    root = ET.fromstring(archive.read('vfs.stream.fast/addon.xml'))
                    self.assertEqual(root.find("requires/import[@addon='kodi.binary.global.main']").get('version'), main)
                    minimum = root.find("requires/import[@addon='xbmc.addon']").get('version')
                    self.assertEqual(minimum, '21.0.0' if codename == 'Omega' else '21.90.1')

    def test_sdk_without_minimum_keeps_current_api_requirement(self):
        self.package('Piers')
        sdk = self.base / 'Piers'
        headers = sdk / 'xbmc/addons/kodi-dev-kit/include/kodi/versions.h'
        headers.write_text('#define ADDON_GLOBAL_VERSION_MAIN "2.0.4"\n'
                           '#define ADDON_INSTANCE_VERSION_VFS "3.0.1"\n', encoding='utf-8')
        root = prepare_manifest(self.source, sdk, 'Piers')
        self.assertEqual(root.find("requires/import[@addon='kodi.binary.global.main']").get('version'),
                         '2.0.4')

    def test_invalid_sdk_minimum_is_rejected(self):
        self.package('Piers')
        sdk = self.base / 'Piers'
        headers = sdk / 'xbmc/addons/kodi-dev-kit/include/kodi/versions.h'
        text = headers.read_text(encoding='utf-8').replace(
            'ADDON_GLOBAL_VERSION_MAIN_MIN "2.0.3"', 'ADDON_GLOBAL_VERSION_MAIN_MIN "2.0.5"')
        headers.write_text(text, encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'MIN exceeds'):
            prepare_manifest(self.source, sdk, 'Piers')

    def test_wrong_tag_does_not_publish_a_misversioned_package(self):
        with self.assertRaisesRegex(ValueError, 'must match'):
            self.package(tag='v0.0.0')
        self.assertFalse((self.base / 'dist').exists())

    def test_macos_cmake_library_is_renamed_for_kodi(self):
        (self.build / 'libvfs.stream.fast.dylib').write_bytes(b'macOS binary')
        package = self.package('Piers', platform='osx-arm64')
        with zipfile.ZipFile(package) as archive:
            self.assertEqual(archive.read('vfs.stream.fast/vfs.stream.fast.dylib'), b'macOS binary')
            self.assertNotIn('vfs.stream.fast/libvfs.stream.fast.dylib', archive.namelist())

    def test_missing_binary_fails_instead_of_publishing_resources_only(self):
        (self.build / 'libvfs.stream.fast.so').unlink()
        version = ET.parse(self.source / 'addon.xml').getroot().get('version')
        with self.assertRaisesRegex(ValueError, 'Expected one'):
            self.package(tag=version)


if __name__ == '__main__':
    unittest.main()
