#!/usr/bin/env python3
"""Regression tests for the Liu2022 protocol implementation."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

PROTOCOLS_PATH = Path(__file__).resolve().parents[1] / "protocols"
if str(PROTOCOLS_PATH) not in sys.path:
    sys.path.insert(0, str(PROTOCOLS_PATH))

import liu2022  # type: ignore  # pylint: disable=import-error


class Liu2022ProtocolTests(unittest.TestCase):
    """Exercise core Liu2022 flows to guard against regressions."""

    def setUp(self) -> None:
        self.ncc = liu2022.NCCState()
        self.gm = self.ncc.register_gm("GM-01")
        self.ap1 = self.ncc.register_ap("AP-01")
        self.ap2 = self.ncc.register_ap("AP-02")
        self.ue = self.ncc.register_ue("UE-01")
        self._negotiate_groups()

    def _negotiate_groups(self) -> None:
        for idx, ap in enumerate((self.ap1, self.ap2), start=1):
            ts = 100_000 * idx
            request = ap.start_group_request(ts)
            response = self.gm.process_group_request(request, now=ts + 5)
            ap.process_group_response(response, now=ts + 10)

        for ap_state in (self.ap1, self.ap2):
            for assignment in ap_state.assignments.values():
                assignment.hac = [
                    liu2022.GroupCredential(record.apgid, record.sgk_bytes, record.expiry_ts)
                    for record in self.gm.ap_groups.values()
                    if record.apgid != assignment.apgid
                ]

    def _perform_access(self) -> None:
        ts1 = 250_000
        request = self.ue.create_access_request(ts1)
        response = self.ap1.handle_access_request(request, now=ts1 + 20)
        self.ue.process_access_response(response, now=ts1 + 40)
        self.assertIsNotNone(self.ue.session_key)

    def test_access_flow_updates_identity_and_session(self) -> None:
        old_pid = self.ue.masked_identity.p_id
        self._perform_access()
        self.assertNotEqual(old_pid, self.ue.masked_identity.p_id)
        self.assertGreater(len(self.ue.lka), 0)

    def test_handover_refreshes_lka_and_session(self) -> None:
        self._perform_access()
        old_session_key = self.ue.session_key
        handover_request = self.ue.create_handover_request("AP-02", 310_000)
        handover_response = self.ap2.process_handover_request(handover_request, now=310_030)
        self.assertGreater(len(handover_response.lka), 0)
        self.ue.process_handover_response(handover_response, now=310_080)
        self.assertIsNotNone(self.ue.session_key)
        self.assertNotEqual(old_session_key, self.ue.session_key)
        self.assertEqual(len(self.ue.lka), len(handover_response.lka))

    def test_group_response_signature_verification(self) -> None:
        ap3 = self.ncc.register_ap("AP-03")
        request = ap3.start_group_request(420_000)
        response = self.gm.process_group_request(request, now=420_010)
        tampered = replace(response, v_gm=liu2022.normalize_scalar(response.v_gm + 1))
        with self.assertRaises(ValueError):
            ap3.process_group_response(tampered, now=420_020)


if __name__ == "__main__":
    unittest.main()
