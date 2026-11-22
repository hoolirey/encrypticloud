import os
import tempfile
import unittest

from node_dispatcher import JobQueue


class JobQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "jobs.sqlite3")
        self.queue = JobQueue(self.db_path)
        self.envelope = {
            "node_id": "test",
            "seq": 1,
            "request": {},
            "approvals": [],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_enqueue_and_get(self):
        job_id = self.queue.enqueue(self.envelope)
        job = self.queue.get(job_id)
        self.assertEqual(job["envelope"], self.envelope)
        self.assertEqual(job["status"], "queued")

    def test_duplicate_envelope_returns_same_job(self):
        first = self.queue.enqueue(self.envelope)
        second = self.queue.enqueue(self.envelope)
        self.assertEqual(first, second)

    def test_job_survives_reopen(self):
        job_id = self.queue.enqueue(self.envelope)
        reopened = JobQueue(self.db_path)
        self.assertEqual(reopened.get(job_id)["envelope"], self.envelope)

    def test_missing_job_returns_none(self):
        self.assertIsNone(self.queue.get("not-a-job"))

    def test_rejects_incomplete_envelope(self):
        with self.assertRaises(ValueError):
            self.queue.enqueue({"node_id": "test"})


if __name__ == "__main__":
    unittest.main()
