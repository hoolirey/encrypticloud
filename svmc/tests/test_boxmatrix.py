"""Tests for svmc.boxmatrix (4D BoxedMatrix with pull recordance)."""

from __future__ import annotations

import unittest

from svmc.boxmatrix import (
    BoxedMatrix4D,
    MatrixIndexError,
    RecordanceError,
    axis_label,
    label_to_axis,
)


class TestAxisLabels(unittest.TestCase):
    def test_origin_label_and_progression(self):
        self.assertEqual(axis_label(0), "A0")
        self.assertEqual(axis_label(9), "A9")
        self.assertEqual(axis_label(10), "B0")
        self.assertEqual(axis_label(35), "D5")
        self.assertEqual(axis_label(40), "E0")
        self.assertEqual(axis_label(259), "Z9")
        self.assertEqual(axis_label(260), "A0")

    def test_label_roundtrip(self):
        for i in (0, 5, 13, 27):
            self.assertEqual(label_to_axis(axis_label(i)), i)

    def test_invalid_label(self):
        with self.assertRaises(MatrixIndexError):
            label_to_axis("AA0")
        with self.assertRaises(MatrixIndexError):
            label_to_axis("9")

    def test_origin_and_far(self):
        m = BoxedMatrix4D(2.5, 2.5, 2.5, cell_size_m=1.0)
        self.assertEqual(m.label((0, 0, 0, 0)), "A0,A0,A0,A0")
        far = m.far_index()
        self.assertEqual(far, (1, 1, 1, 1))
        self.assertEqual(m.far_label(), "A1,A1,A1,A1")


class TestBoxedMatrixDimensions(unittest.TestCase):
    def test_extents_from_si_dimensions(self):
        m = BoxedMatrix4D(2.5, 3.9, 1.7, cell_size_m=1.0)
        self.assertEqual(m.extents, (2, 3, 1))

    def test_variable_box_size(self):
        m1 = BoxedMatrix4D(10.0, 10.0, 10.0, cell_size_m=1.0)
        m2 = BoxedMatrix4D(10.0, 10.0, 10.0, cell_size_m=2.5)
        self.assertEqual(m1.extents, (10, 10, 10))
        self.assertEqual(m2.extents, (4, 4, 4))
        self.assertAlmostEqual(m2.cell_volume_m3(), 15.625)

    def test_invalid_dimensions(self):
        with self.assertRaises(ValueError):
            BoxedMatrix4D(0.0, 1.0, 1.0)
        with self.assertRaises(ValueError):
            BoxedMatrix4D(1.0, -1.0, 1.0)
        with self.assertRaises(ValueError):
            BoxedMatrix4D(1.0, 1.0, 1.0, cell_size_m=float("inf"))
        with self.assertRaises(ValueError):
            BoxedMatrix4D(1.0, 1.0, 1.0, cell_size_m=2.0)

    def test_max_w_follows_cubic_dimensions(self):
        m = BoxedMatrix4D(4.0, 4.0, 4.0, cell_size_m=1.0)
        self.assertEqual(m.max_w, 3 * 3 * 3)


class TestWXYZRelation(unittest.TestCase):
    def setUp(self):
        self.m = BoxedMatrix4D(4.0, 4.0, 4.0, cell_size_m=1.0)

    def test_put_pull_roundtrip(self):
        self.m.put((1, 2, 3, 6), "payload")
        self.assertEqual(self.m.pull((1, 2, 3, 6)), "payload")
        self.assertEqual(self.m.count(), 1)

    def test_wrong_w_rejected(self):
        with self.assertRaises(MatrixIndexError):
            self.m.put((1, 2, 3, 7), "invented")
        with self.assertRaises(MatrixIndexError):
            self.m.pull((2, 2, 2, 9))

    def test_out_of_bounds_rejected(self):
        with self.assertRaises(MatrixIndexError):
            self.m.put((4, 0, 0, 0), "x")
        with self.assertRaises(MatrixIndexError):
            self.m.pull((-1, 0, 0, 0))

    def test_non_integer_w_rejected(self):
        with self.assertRaises(MatrixIndexError):
            self.m.put((1, 2, 3, 6.0), "float-w")

    def test_missing_cell_pull_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self.m.pull((0, 0, 0, 0))

    def test_zero_cell_has_w_zero(self):
        self.m.put((0, 3, 3, 0), "edge")
        self.assertEqual(self.m.pull((0, 3, 3, 0)), "edge")

    def test_missing_tuple_shape(self):
        with self.assertRaises(MatrixIndexError):
            self.m.put((1, 2, 6), "short")
        with self.assertRaises(MatrixIndexError):
            self.m.put([1, 2, 3, 6], "list")


class TestPullRecordance(unittest.TestCase):
    def setUp(self):
        self.m = BoxedMatrix4D(
            3.0, 3.0, 3.0, cell_size_m=1.0, geo_anchor=(51.5, -0.12)
        )

    def test_chain_of_operations_verifies(self):
        self.m.put((1, 1, 1, 1), "a")
        self.m.put((2, 1, 1, 2), "b")
        self.m.pull((1, 1, 1, 1))
        self.m.clear_cell((2, 1, 1, 2))
        self.assertTrue(self.m.verify())

    def test_tamper_detected(self):
        self.m.put((1, 1, 1, 1), "a")
        self.m.put((2, 1, 1, 2), "b")
        self.assertTrue(self.m.verify())
        self.m._record_entries[0]["op"] = "tampered"
        with self.assertRaises(RecordanceError):
            self.m.verify()

    def test_chain_links(self):
        self.m.put((1, 1, 1, 1), "a")
        self.m.put((2, 1, 1, 2), "b")
        entries = self.m.recordance()
        self.assertEqual(entries[0]["prev_hash"], BoxedMatrix4D.GENESIS_HASH)
        self.assertEqual(entries[1]["prev_hash"], entries[0]["hash"])

    def test_recording_can_be_disabled(self):
        m = BoxedMatrix4D(2.0, 2.0, 2.0, cell_size_m=1.0, recording=False)
        m.put((1, 1, 1, 1), "x")
        self.assertEqual(m.recordance(), [])
        self.assertTrue(m.verify())


class TestGeoOverlay(unittest.TestCase):
    def test_anchor_column_bounds(self):
        m = BoxedMatrix4D(
            4.0, 4.0, 4.0, cell_size_m=1.0, geo_anchor=(51.5, -0.12)
        )
        (lat0, lon0, bottom), (lat1, lon1, top) = m.geo_bounds((0, 0, 0, 0))
        self.assertAlmostEqual(lat0, 51.5)
        self.assertAlmostEqual(lon0, -0.12)
        self.assertAlmostEqual(bottom, 0.0)
        self.assertGreater(lat1, lat0)
        self.assertGreater(lon1, lon0)
        self.assertAlmostEqual(top, 1.0)

    def test_offset_column_shifts_bounds(self):
        m = BoxedMatrix4D(
            4.0, 4.0, 4.0, cell_size_m=1.0, geo_anchor=(51.5, -0.12)
        )
        (lat0, lon0, _), _ = m.geo_bounds((2, 1, 0, 0))
        self.assertGreater(lat0, 51.5)
        self.assertGreater(lon0, -0.12)

    def test_no_anchor(self):
        m = BoxedMatrix4D(4.0, 4.0, 4.0, cell_size_m=1.0)
        with self.assertRaises(MatrixIndexError):
            m.geo_bounds((1, 1, 1, 1))

    def test_invalid_index_still_rejected_in_geo(self):
        m = BoxedMatrix4D(
            4.0, 4.0, 4.0, cell_size_m=1.0, geo_anchor=(51.5, -0.12)
        )
        with self.assertRaises(MatrixIndexError):
            m.geo_bounds((0, 0, 0, 1))


if __name__ == "__main__":
    unittest.main()
