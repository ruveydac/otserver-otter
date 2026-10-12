#!/usr/bin/env python3
"""Run with python3 -B databases/test_generate_database.py."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import generate_database as generator


class DatabaseGenerationTests(unittest.TestCase):
    def test_compiled_tables_are_current(self):
        expected = generator.OUTPUT.read_bytes()
        with TemporaryDirectory() as directory:
            with patch.object(generator, "OUTPUT", Path(directory) / "tables.rs"):
                generator.main()
                self.assertEqual(generator.OUTPUT.read_bytes(), expected)

    def test_namespaces_entities_language_fallback_and_duplicate_ids(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.multiple(generator, MAN_ID=root / "manufacturers.xml",
                                PROFILE_ID=root / "profiles.xml", OUTPUT=root / "tables.rs"):
                manufacturers = '''<Table xmlns="urn:manufacturers">
                  <!-- <Manufacturer ID="1"><ManufacturerInfo><ManufacturerName>Ignored</ManufacturerName></ManufacturerInfo></Manufacturer> -->
                  <Manufacturer ID="2"><ManufacturerInfo><ManufacturerName> A &amp; &quot;B&quot; </ManufacturerName></ManufacturerInfo></Manufacturer>
                  <Manufacturer ID="1"><ManufacturerInfo><ManufacturerName> First </ManufacturerName></ManufacturerInfo></Manufacturer>
                  <Manufacturer ID="3"><ManufacturerInfo/></Manufacturer>
                </Table>'''
                generator.MAN_ID.write_text(manufacturers, encoding="utf-8")
                generator.PROFILE_ID.write_text('''<p:Table xmlns:p="urn:profiles">
                  <p:Profile EndID="2" ID="1"><p:ProfileInfo><p:ProfileName xml:lang="de">Deutsch</p:ProfileName><p:ProfileName xml:lang="en"> English &amp; more </p:ProfileName></p:ProfileInfo></p:Profile>
                  <p:Profile ID="3" EndID="4"><p:ProfileInfo><p:ProfileName xml:lang="de">Fallback</p:ProfileName></p:ProfileInfo></p:Profile>
                  <p:Profile ID="5" EndID="6"><p:ProfileInfo/></p:Profile>
                </p:Table>''', encoding="utf-8")
                generator.main()
                output = generator.OUTPUT.read_text(encoding="utf-8")
                self.assertIn('    (1, "First"),\n    (2, "A & \\"B\\""),', output)
                self.assertNotIn("Ignored", output)
                for row in ['(1, 2, "English & more")', '(3, 4, "Fallback")', '(5, 6, "")']:
                    self.assertIn(row, output)
                generator.MAN_ID.write_text(manufacturers.replace('ID="2"', 'ID="1"'), encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "duplicate manufacturer IDs"):
                    generator.main()


if __name__ == "__main__":
    unittest.main()
