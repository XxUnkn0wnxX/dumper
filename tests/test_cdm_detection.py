"""Run the actual Frida JavaScript against simulated APIs, without a device."""

from pathlib import Path
import shutil
import subprocess
import unittest


# ---------------------------------------------------------------------------
# NODE HARNESS
# The companion JavaScript file supplies simulated Frida APIs; this test only
# launches that harness and therefore does not require a live device. Missing
# Node.js is handled by the skip decorator on the test method.
# ---------------------------------------------------------------------------
class CdmJavaScriptTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for the JavaScript tests')
    def test_cdm_detection_and_hook_initialization(self):
        # Use the sibling .js harness so Python validates the actual agent
        # source through Node, while capturing output for actionable failures.
        result = subprocess.run(
            [shutil.which('node'), str(Path(__file__).with_suffix('.js'))],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


# Running this file directly invokes the focused Node-backed test in this
# module.
if __name__ == '__main__':
    unittest.main()
