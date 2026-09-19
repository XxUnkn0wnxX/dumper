"""Run the actual Frida JavaScript against simulated APIs, without a device."""

from pathlib import Path
import shutil
import subprocess
import unittest


class CdmJavaScriptTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for the JavaScript tests')
    def test_cdm_detection_and_hook_initialization(self):
        result = subprocess.run(
            [shutil.which('node'), str(Path(__file__).with_suffix('.js'))],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
