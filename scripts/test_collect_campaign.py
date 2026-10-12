"""Counter regressions could falsely close a security gate: test pending and failed runs."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("campaign", pathlib.Path(__file__).with_name("collect-campaign.py"))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


class CampaignEvidenceTest(unittest.TestCase):
    def test_pending_jobs_are_not_a_measurement(self):
        run = dict(id=1, head_sha="abc", html_url="test", run_attempt=1, status="in_progress")
        jobs = [dict(name="android over real Tor to onion relays (emulator)", status="queued") for _ in range(20)]
        result = campaign.summarize("tor", run, jobs)
        self.assertFalse(result["tor_measurement_complete"])
        self.assertIsNone(result["tor_non_success_rate"])
        self.assertEqual(0, result["passed"])

    def test_no_failure_cancel_or_skip_is_counted_as_a_pass(self):
        run = dict(id=1, head_sha="abc", html_url="test", run_attempt=1, status="completed", conclusion="failure")
        outcomes = ["success"] * 17 + ["failure", "cancelled", "skipped"]
        jobs = [dict(name="android over real Tor to onion relays (emulator)", status="completed", conclusion=o) for o in outcomes]
        jobs.append(dict(name="plan", status="completed", conclusion="success"))
        result = campaign.summarize("tor", run, jobs)
        self.assertEqual(20, result["scheduled"])
        self.assertEqual(17, result["passed"])
        self.assertEqual(0.15, result["tor_non_success_rate"])


if __name__ == "__main__":
    unittest.main()
