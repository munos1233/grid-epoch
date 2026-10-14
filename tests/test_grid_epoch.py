import json
import os
import secrets
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from grid_epoch.ack import ZALL_LEN, encode_zall, encode_zdet, xor_tags
from grid_epoch.aead import open_aead, seal
from grid_epoch.crypto import hmac_sm3, parallel_update, provision_table, seed_pair_native, sm3, sm4_block, stream_ack, stream_topology
from grid_epoch.crypto import free_table
from grid_epoch.cosign import ClientShare, CollaborativeSM2
from grid_epoch.custody import restore_masters, seal_masters
from grid_epoch.custodian import open_share_sink
from grid_epoch.desk import OperatorDesk
from grid_epoch.derive import (
    STREAM_COUNTY_WIDTH,
    auth_key,
    biz_key,
    city_biz,
    city_mgmt,
    completion_tag,
    county_biz,
    county_mgmt,
    cs_open_key,
    descend_from,
    make_tid,
    seed_biz,
    seed_mgmt,
    zone_key,
)
from grid_epoch.timekey import ERA, TimeFrontier, time_leaf
from grid_epoch.errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked
from grid_epoch.kmc import ProvincialKMC
from grid_epoch.package import attach_signatures, extract_for_leaf, parse_terminal_package
from grid_epoch.subsetdiff import cover_choice, live_leaves, planned_cover, sd_cover
from grid_epoch.subtree import county_index, county_zone_count
from grid_epoch.tree import cover_nodes, path_nodes, subtree_leaf_range


SM3_ABC = bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
SM4_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
SM4_PT = SM4_KEY
SM4_CT = bytes.fromhex("681edf34d206965e86b3e94f536e4246")


class PrimitiveTest(unittest.TestCase):
    def test_sm3_and_sm4_vectors(self):
        self.assertEqual(sm3(b"abc"), SM3_ABC)
        self.assertEqual(sm4_block(SM4_KEY, SM4_PT), SM4_CT)

    def test_kdf_matches_native_batch_layout(self):
        mk_mgmt = bytes(range(32))
        mk_biz = bytes(range(32, 64))
        area, cohort, zone, local = 330100, 3, 42, 7
        tid = make_tid(zone, local)
        county = 0
        expect_m = seed_mgmt(zone_key(county_mgmt(city_mgmt(mk_mgmt, cohort), county), area, zone), tid)
        expect_b = seed_biz(county_biz(city_biz(mk_biz, area, cohort), county), zone, tid)
        got_m, got_b = seed_pair_native(mk_mgmt, mk_biz, area, cohort, county, zone, tid)
        self.assertEqual(got_m, expect_m)
        self.assertEqual(got_b, expect_b)

    def test_stream_xor_matches_python(self):
        self.assertEqual(county_zone_count(1 << 17), STREAM_COUNTY_WIDTH)
        self.assertEqual(STREAM_COUNTY_WIDTH, 256)
        self.assertEqual(county_zone_count(2), 1)
        mk_mgmt = os.urandom(32)
        mk_biz = os.urandom(32)
        cohort = 4
        width = county_zone_count(2)
        xor_m, xor_b = stream_topology(mk_mgmt, mk_biz, 11, cohort, 5, 2, 3, width, 2)
        acc_m = bytearray(32)
        acc_b = bytearray(32)
        managed = city_mgmt(mk_mgmt, cohort)
        business = city_biz(mk_biz, 11, cohort)
        for zone in range(5, 7):
            county = zone // width
            zk = zone_key(county_mgmt(managed, county), 11, zone)
            business_county = county_biz(business, county)
            for local in range(3):
                tid = make_tid(zone, local)
                for acc, block in (
                    (acc_m, seed_mgmt(zk, tid)),
                    (acc_b, seed_biz(business_county, zone, tid)),
                ):
                    for i, value in enumerate(block):
                        acc[i] ^= value
        self.assertEqual(xor_m, bytes(acc_m))
        self.assertEqual(xor_b, bytes(acc_b))

    def test_aead_roundtrip_and_tamper(self):
        key = os.urandom(16)
        blob = seal(key, b"telemetry")
        self.assertEqual(open_aead(key, blob), b"telemetry")
        broken = bytearray(blob)
        broken[-1] ^= 0x01
        with self.assertRaises(Exception):
            open_aead(key, bytes(broken))


class TreeTest(unittest.TestCase):
    def test_cover_partitions_live_leaves(self):
        n = 8
        revoked = {0}
        cover = cover_nodes(n, revoked)
        self.assertEqual(cover, [3, 5, 9])
        for leaf in range(n):
            hit = [node for node in path_nodes(leaf, n) if node in cover]
            if leaf in revoked:
                self.assertEqual(hit, [])
            else:
                self.assertEqual(len(hit), 1)

    def test_empty_and_full_revocation(self):
        self.assertEqual(cover_nodes(16, set()), [1])
        self.assertEqual(cover_nodes(8, set(range(8))), [])

    def test_cover_size_bound(self):
        n = 32
        revoked = {1, 2, 9, 14}
        cover = cover_nodes(n, revoked)
        self.assertLessEqual(len(cover), len(revoked) * n.bit_length())
        for leaf in range(n):
            hit = [node for node in path_nodes(leaf, n) if node in set(cover)]
            self.assertEqual(len(hit), 0 if leaf in revoked else 1)

    def test_single_revoke_at_million_scale_is_log(self):
        n = 1 << 20
        for leaf in (0, 123456, n - 1):
            self.assertEqual(len(cover_nodes(n, {leaf})), 20)

    def test_internal_node_traces_only_its_subtree(self):
        n = 16
        start, end = subtree_leaf_range(n, 3)
        self.assertEqual((start, end), (8, 16))
        self.assertGreater(end - start, 1)
        for leaf in range(start, end):
            self.assertIn(3, path_nodes(leaf, n))
        for leaf in range(0, start):
            self.assertNotIn(3, path_nodes(leaf, n))
        self.assertEqual(subtree_leaf_range(n, n + 4), (4, 5))

    def test_subset_difference_partitions_live_leaves(self):
        n = 16
        for mask in range(1 << n):
            revoked = {leaf for leaf in range(n) if mask & (1 << leaf)}
            subsets = sd_cover(n, revoked)
            seen: set[int] = set()
            for subset in subsets:
                leaves = live_leaves(n, subset)
                self.assertTrue(seen.isdisjoint(leaves))
                seen.update(leaves)
            self.assertEqual(seen, set(range(n)) - revoked)
            self.assertLessEqual(len(subsets), max(0, 2 * len(revoked) - 1) if revoked else 1)

    def test_full_block_uses_complete_subtree_and_scatter_uses_subset_difference(self):
        n = 64
        grain = 8
        revoked = set(range(8, 16))
        self.assertEqual(cover_choice(n, revoked, grain), "sd")
        kind, subsets = planned_cover(n, revoked, grain)
        self.assertEqual(kind, "sd")
        self.assertEqual(len(subsets), 1)
        self.assertLess(len(subsets), len(revoked))
        scattered = {0, 2, 5, 9}
        kind, subsets = planned_cover(n, scattered, grain)
        self.assertEqual(kind, "sd")
        self.assertEqual(subsets, sd_cover(n, scattered))
        self.assertEqual(cover_choice(n, set(), grain), "cs")

    def test_hanging_labels_match_terminal_key_count_and_not_path_keys(self):
        from grid_epoch.derive import node_key_at
        from grid_epoch.sdkey import continue_walk, cover_subset_key, epoch_secret, stubs_for_leaf, walk_label
        from grid_epoch.subsetdiff import sd_terminal_keys

        master = os.urandom(32)
        stubs = stubs_for_leaf(1 << 20, 123456, master)
        self.assertEqual(len(stubs), sd_terminal_keys(1 << 20))
        secret = epoch_secret(master, 1)
        subset = cover_subset_key(master, secret, 1, 3)
        self.assertNotEqual(subset, node_key_at(master, 1, 0, b"NODE"))
        self.assertNotEqual(subset, node_key_at(master, 3, 0, b"NODE"))
        self.assertNotEqual(cover_subset_key(master, secret, 1, 3), cover_subset_key(master, epoch_secret(master, 0), 1, 3))
        self.assertEqual(walk_label(master, 1, 9), continue_walk(walk_label(master, 1, 4), 4, 9))


class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.kmc = ProvincialKMC(area=330100)
        self.kmc.arm_escrow("甲", "乙")
        self.kmc.create_cohort(1, 16)
        self.gateway = self.kmc.register_zone(42, 1)
        self.terminals = [self.kmc.enroll(42, i) for i in range(4)]

    def activate(self):
        release = self.kmc.publish(1)
        self.gateway.sync(release.gateway)
        self.gateway.sync_revocation(release.revocation, self.kmc.proofs_for_zone(42))
        for terminal in self.terminals:
            terminal.apply(release.terminal)
        return release

    def test_epoch_zero_rejects_business(self):
        self.assertEqual(self.terminals[0].epoch, 0)
        with self.assertRaises(EpochRejected):
            self.terminals[0].seal_telemetry(b"early")
        with self.assertRaises(EpochRejected):
            self.gateway.accept_and_wrap(b"early")
        blob = b"GE02" + struct.pack(">II", 42, 0) + b"\x00" * 64
        with self.assertRaises(EpochRejected):
            self.kmc.open_uplink(blob)
        with self.assertRaises(EpochRejected):
            self.terminals[0].completion_tag()
        with self.assertRaises(EpochRejected):
            self.gateway.completion_report()

    def test_graded_auth_and_encryption(self):
        self.activate()
        challenge = os.urandom(16)
        proof = self.terminals[0].prove(challenge)
        self.assertTrue(self.gateway.verify_proof(self.terminals[0].tid, challenge, proof))
        self.assertFalse(self.gateway.verify_proof(make_tid(42, 500), challenge, proof))
        hidden = self.terminals[1].tid
        saved = self.gateway.leaf_of.pop(hidden)
        self.assertFalse(self.gateway.verify_proof(hidden, challenge, proof))
        self.gateway.leaf_of[hidden] = saved
        payload = b"Ua=10.2;Ia=5"
        wrapped = self.gateway.accept_and_wrap(self.terminals[0].seal_telemetry(payload))
        self.assertEqual(self.kmc.open_uplink(wrapped), payload)
        with self.assertRaises(PermissionError):
            self.gateway.derive_business_key(self.terminals[0].tid)
        _tid, _epoch, sealed, _mac, _body = __import__(
            "grid_epoch.kmc", fromlist=["_split_terminal_record"]
        )._split_terminal_record(self.terminals[0].seal_telemetry(payload))
        key_auth, _key_biz = self.terminals[0].device_keys()
        for wrong in (key_auth, self.gateway.link_key, self.gateway.zone_mgmt[:16], self.gateway.path_keys[1]):
            with self.assertRaises(Exception):
                open_aead(wrong, sealed)

    def test_epoch_jump_and_replay(self):
        first = self.kmc.publish(1)
        second = self.kmc.publish(1)
        self.assertEqual(first.revocation, second.revocation)
        self.assertEqual(first.rev_version, second.rev_version)
        self.assertNotIn(0, parse_terminal_package(second.terminal).entries)
        self.gateway.sync(second.gateway)
        self.gateway.sync_revocation(second.revocation, self.kmc.proofs_for_zone(42))
        self.assertEqual(self.gateway.epoch, 2)
        for terminal in self.terminals:
            terminal.apply(second.terminal)
            self.assertEqual(terminal.epoch, 2)
            self.assertEqual(terminal.device_keys(), self.kmc.device_keys(terminal.tid))
            self.assertFalse(terminal.biz_frontier.covers(1))
            self.assertFalse(terminal.auth_frontier.covers(1))
            _seed_m, seed_b = self.kmc._seeds(self.kmc.registry[terminal.tid])
            self.assertEqual(
                self.kmc.business_key_at(terminal.tid, 1),
                biz_key(time_leaf(seed_b, 1), 1, self.kmc.cohorts[1].nonces[1]),
            )
            with self.assertRaises(EpochRejected):
                terminal.apply(first.terminal)
        payload = b"after-epoch"
        self.assertEqual(
            self.kmc.open_uplink(self.gateway.accept_and_wrap(self.terminals[1].seal_telemetry(payload))),
            payload,
        )

    def test_revocation_excludes_terminal_and_keeps_others(self):
        self.activate()
        victim = self.terminals[2]
        self.kmc.revoke(victim.tid)
        release = self.kmc.publish(1)
        self.gateway.revoked_tids.clear()
        self.gateway.sync(release.gateway)
        self.gateway.sync_revocation(release.revocation, self.kmc.proofs_for_zone(42))
        self.assertEqual(self.gateway.leaf_status(victim.leaf), "revoked")
        for terminal in self.terminals:
            if terminal.tid == victim.tid:
                continue
            terminal.apply(release.terminal)
            self.assertEqual(terminal.device_keys(), self.kmc.device_keys(terminal.tid))
        with self.assertRaises(TerminalRevoked):
            victim.apply(release.terminal)
        self.assertEqual(victim.epoch, 1)
        self.assertNotEqual(victim.device_keys()[0], self.kmc.device_keys(victim.tid)[0])
        with self.assertRaises(TerminalRevoked):
            self.gateway.accept_and_wrap(victim.seal_telemetry(b"stale"))
        parsed = parse_terminal_package(release.terminal)
        self.assertEqual(parsed.cover, "sd")
        from grid_epoch.aead import CryptoError

        subset_id, blob = next(iter(parsed.entries.items()))
        for key in victim.path_keys.values():
            with self.assertRaises(CryptoError):
                open_aead(key, blob)
        self.assertIsInstance(subset_id, tuple)

    def test_stale_revocation_root_rejected(self):
        first = self.activate()
        self.kmc.revoke(self.terminals[3].tid)
        second = self.kmc.publish(1)
        self.gateway.sync(second.gateway)
        with self.assertRaises(EpochRejected):
            self.gateway.sync_revocation(first.revocation, self.kmc.proofs_for_zone(42))

    def test_tampered_signature_rejected(self):
        release = self.kmc.publish(1)
        parsed = parse_terminal_package(release.terminal)
        self.assertEqual(len(parsed.signatures), 1)
        self.assertEqual(len(parsed.sm2_signature()), 64)
        package = bytearray(release.terminal)
        package[-1] ^= 0x01
        with self.assertRaises(EpochRejected):
            self.terminals[0].apply(bytes(package))
        extra = attach_signatures(parsed.raw_body, [(1, parsed.sm2_signature()), (2, b"\x11" * 32)])
        with self.assertRaises(ValueError):
            parse_terminal_package(extra)

    def test_completion_tag_uses_business_leaf(self):
        self.activate()
        terminal = self.terminals[0]
        leaf = terminal.biz_frontier.current_leaf()
        real = terminal.completion_tag()
        self.assertEqual(
            real,
            completion_tag(leaf, terminal.zone_id, terminal.tid, terminal.epoch, terminal.nonce),
        )
        message = b"ACK1" + struct.pack(">IQI", terminal.zone_id, terminal.tid, terminal.epoch)
        auth, _biz = terminal.device_keys()
        self.assertNotEqual(hmac_sm3(auth, message)[:16], real)
        self.assertNotEqual(hmac_sm3(self.gateway.zone_mgmt[:16], message)[:16], real)
        self.assertNotEqual(hmac_sm3(terminal.path_keys[1], message)[:16], real)
        self.assertNotEqual(
            completion_tag(self.gateway.zone_mgmt, terminal.zone_id, terminal.tid, terminal.epoch, terminal.nonce),
            real,
        )
        self.assertNotEqual(
            completion_tag(leaf, terminal.zone_id, terminal.tid, terminal.epoch + 1, terminal.nonce),
            real,
        )
        self.assertNotEqual(
            completion_tag(leaf, terminal.zone_id, terminal.tid + 1, terminal.epoch, terminal.nonce),
            real,
        )
        flipped = bytes([terminal.nonce[0] ^ 0x01]) + terminal.nonce[1:]
        self.assertNotEqual(
            completion_tag(leaf, terminal.zone_id, terminal.tid, terminal.epoch, flipped),
            real,
        )

    def test_zone_completion_is_checked_by_master(self):
        self.activate()
        for terminal in self.terminals:
            self.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
        token = self.gateway.completion_report()
        self.assertEqual(len(token), ZALL_LEN)
        self.assertTrue(token.startswith(b"ZALL"))
        confirmed = self.kmc.accept_report(42, token)
        self.assertEqual(confirmed, {terminal.tid for terminal in self.terminals})
        broken = bytearray(token)
        broken[-1] ^= 0x01
        with self.assertRaises(AuthFailed):
            self.kmc.accept_report(42, bytes(broken))
        self.assertEqual(self.kmc.confirmed[1], confirmed)

        victim = self.terminals[3]
        self.kmc.revoke(victim.tid)
        self.gateway.reset_acks()
        for terminal in self.terminals:
            if terminal.tid == victim.tid:
                continue
            self.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
        partial = self.gateway.completion_report()
        self.assertTrue(partial.startswith(b"ZALL"))
        live = self.kmc.accept_report(42, partial)
        self.assertNotIn(victim.tid, live)
        self.assertEqual(len(live), 3)

    def test_conflicting_tag_drops_that_terminal(self):
        self.activate()
        terminal = self.terminals[0]
        self.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
        flipped = bytearray(terminal.completion_tag())
        flipped[0] ^= 0x01
        self.gateway.submit_ack(terminal.tid, terminal.ack(), bytes(flipped))
        for other in self.terminals[1:]:
            self.gateway.submit_ack(other.tid, other.ack(), other.completion_tag())
        report = self.gateway.completion_report()
        self.assertTrue(report.startswith(b"ZEXC"))
        accepted = self.kmc.accept_report(42, report)
        self.assertNotIn(terminal.tid, accepted)
        self.assertEqual(accepted, {item.tid for item in self.terminals[1:]})

    def test_withheld_completion_is_rejected_and_localized(self):
        self.activate()
        withheld = self.terminals[1]
        present = [terminal for terminal in self.terminals if terminal is not withheld]
        for terminal in present:
            self.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
        forged = encode_zall(
            42,
            self.gateway.epoch,
            len(self.terminals),
            xor_tags([terminal.completion_tag() for terminal in present]),
            self.gateway.link_key,
        )
        revoked = set(self.kmc.cohorts[1].terminals.revoked)
        epoch = self.kmc.cohorts[1].epoch
        with self.assertRaises(AuthFailed):
            self.kmc.accept_report(42, forged)
        self.assertEqual(set(self.kmc.cohorts[1].terminals.revoked), revoked)
        self.assertEqual(self.kmc.cohorts[1].epoch, epoch)
        self.assertEqual(self.kmc.confirmed[1], set())
        partial = self.gateway.completion_report()
        self.assertTrue(partial.startswith(b"ZEXC"))
        accepted = self.kmc.accept_report(42, partial)
        self.assertEqual(accepted, {terminal.tid for terminal in present})
        self.assertNotIn(withheld.tid, accepted)
        named = self.kmc.localize_report(42, self.gateway.detail_report())
        self.assertEqual({terminal.tid for terminal in self.terminals} - named, {withheld.tid})
        good = present[0]
        flipped = bytearray(good.completion_tag())
        flipped[0] ^= 0x01
        detail = encode_zdet(
            42,
            self.gateway.epoch,
            [(good.tid & 0xFFFF, bytes(flipped)), (present[1].tid & 0xFFFF, present[1].completion_tag())],
            self.gateway.link_key,
        )
        matched = self.kmc.localize_report(42, detail)
        self.assertIn(present[1].tid, matched)
        self.assertNotIn(good.tid, matched)
        later = self.kmc.publish(1)
        self.gateway.sync(later.gateway)
        self.gateway.sync_revocation(later.revocation, self.kmc.proofs_for_zone(42))
        withheld.apply(later.terminal)
        self.assertEqual(withheld.epoch, later.epoch)
        with self.assertRaises(EpochRejected):
            self.kmc.accept_report(42, forged)

    def test_gateway_revocation_replaces_slot_without_rotating_zone(self):
        self.activate()
        terminal = self.terminals[0]
        challenge = os.urandom(16)
        old_zone = bytes(self.gateway.zone_mgmt)
        old_path = dict(terminal.path_keys)
        self.assertTrue(self.gateway.verify_proof(terminal.tid, challenge, terminal.prove(challenge)))
        replacement = self.kmc.revoke_gateway(42)
        self.assertEqual(replacement.zone_mgmt, old_zone)
        self.assertEqual(terminal.path_keys, old_path)
        self.assertNotEqual(replacement.leaf, self.gateway.leaf)
        release = self.kmc.publish(1)
        with self.assertRaises(TerminalRevoked):
            self.gateway.sync(release.gateway)
        replacement.sync(release.gateway)
        replacement.sync_revocation(release.revocation, self.kmc.proofs_for_zone(42))
        terminal.apply(release.terminal)
        self.assertEqual(terminal.path_keys, old_path)
        self.assertEqual(terminal.seed_mgmt, seed_mgmt(old_zone, terminal.tid))
        self.assertTrue(replacement.verify_proof(terminal.tid, challenge, terminal.prove(challenge)))
        gone = self.terminals[1]
        challenge_gone = os.urandom(16)
        kept = gone.sign_enrollment(challenge_gone)
        signed_epoch = gone.epoch
        self.kmc.destroy_record(gone.tid)
        replacement.note_destroyed(gone.tid)
        again = self.kmc.revoke_gateway(42)
        later = self.kmc.publish(1)
        again.sync(later.gateway)
        again.sync_revocation(later.revocation, self.kmc.proofs_for_zone(42))
        gone.apply(later.terminal)
        with self.assertRaises(TerminalRevoked) as blocked:
            again.accept_and_wrap(gone.seal_telemetry(b"after-slot"))
        self.assertEqual(str(blocked.exception), "终端已销毁")
        self.assertFalse(again.verify_enrollment(gone.tid, 1, challenge_gone, kept, signed_epoch))
        self.assertFalse(self.kmc.verify_enrollment(gone.tid, challenge_gone, kept, signed_epoch))
        self.assertNotIn(gone.leaf, self.kmc.cohorts[1].terminals.revoked)

    def test_replacement_keeps_neighbors_on_the_same_path_keys(self):
        self.activate()
        victim = self.terminals[2]
        skipper = self.terminals[1]
        neighbor = self.terminals[0]
        old_root = neighbor.path_keys[1]
        self.kmc.revoke(victim.tid)
        renewed = self.kmc.enroll(42, 99)
        self.assertNotEqual(renewed.leaf, victim.leaf)
        self.assertEqual(neighbor.path_keys[1], old_root)
        release = self.kmc.publish(1)
        self.gateway.sync(release.gateway)
        self.gateway.sync_revocation(release.revocation, self.kmc.proofs_for_zone(42))
        neighbor.apply(release.terminal)
        renewed.apply(release.terminal)
        skipper.apply(release.terminal)
        self.assertEqual(neighbor.device_keys(), self.kmc.device_keys(neighbor.tid))
        self.assertEqual(renewed.device_keys(), self.kmc.device_keys(renewed.tid))
        self.assertEqual(skipper.device_keys(), self.kmc.device_keys(skipper.tid))
        self.assertEqual(neighbor.path_keys[1], old_root)
        with self.assertRaises(TerminalRevoked):
            victim.apply(release.terminal)
        with self.assertRaises(TerminalRevoked):
            self.gateway.accept_and_wrap(victim.seal_telemetry(b"old-tid"))

    def test_gateway_capacity_follows_zone_count(self):
        from grid_epoch.merkle import RevocationTree

        city = self.kmc.create_cohort(9, 1 << 20)
        self.assertEqual(city.terminals.n, 1 << 20)
        self.assertEqual(city.gateways.n, 8192)
        tree = RevocationTree(1 << 20, {0})
        self.assertEqual(len(tree.root()), 32)
        self.assertEqual(len(tree.proof(123456)), 20)


    def test_services_nonces_and_city_boundary(self):
        from grid_epoch.aead import CryptoError
        from grid_epoch.device import DeviceKey, open_provision
        from grid_epoch.subtree import Subtree

        self.activate()
        terminal = self.terminals[0]
        energy = terminal.seal_telemetry(b"kwh")
        with self.assertRaises(PermissionError):
            self.gateway.open_energy(energy)
        _auth, biz = terminal.device_keys()
        ctrl = terminal.control_key()
        from grid_epoch.services import parse_record

        _service, _tid, _epoch, _counter, sealed, _mac, _body = parse_record(energy)
        with self.assertRaises(CryptoError):
            open_aead(ctrl, sealed)
        self.assertNotEqual(biz_key(terminal.biz_frontier.current_leaf(), terminal.epoch, terminal.auth_nonce), biz)
        wrapped = self.gateway.accept_and_wrap(energy)
        self.assertEqual(self.kmc.open_uplink(wrapped), b"kwh")
        with self.assertRaises(AuthFailed):
            self.kmc.open_uplink(wrapped)
        control = terminal.seal_control(b"trip")
        self.assertEqual(self.gateway.open_control(control), b"trip")
        again = terminal.seal_control(b"trip-2")
        wrapped_control = self.gateway.accept_and_wrap(again)
        self.assertEqual(self.kmc.open_uplink(wrapped_control), b"trip-2")
        other = DeviceKey()
        with self.assertRaises(ProtocolError):
            open_provision(other, terminal.provision_blob)
        other.discard()
        with self.assertRaises(ProtocolError) as destroyed_key:
            open_provision(other, terminal.provision_blob)
        self.assertEqual(str(destroyed_key.exception), "终端已销毁")
        city = self.kmc.cities[1]
        self.assertFalse(any(name.startswith("mk_") or name in {"_mk_mgmt", "_mk_biz", "_sm9_master"} for name in city.__dict__))
        for value in city.__dict__.values():
            self.assertNotEqual(value, self.kmc.hsm._mk_mgmt)
            self.assertNotEqual(value, self.kmc.hsm._mk_biz)
        tree = Subtree(16, b"m" * 32, b"NODE", 4)
        first = tree.allocate(0)
        tree.revoked.add(first)
        self.assertNotEqual(tree.allocate(0), first)
        tree.revoke_span(1)
        self.assertTrue({4, 5, 6, 7} <= tree.revoked)
        with self.assertRaises(ProtocolError):
            tree.allocate(1)

    def test_drop_expired_nonce_and_time_era(self):
        self.activate()
        later = self.kmc.publish(1)
        for terminal in self.terminals:
            terminal.apply(later.terminal)
        tid = self.terminals[0].tid
        self.assertEqual(len(self.kmc.business_key_at(tid, 1)), 16)
        with self.assertRaises(ProtocolError):
            self.kmc.drop_expired(1, 3)
        self.kmc.drop_expired(1, 2)
        with self.assertRaises(EpochRejected):
            self.kmc.business_key_at(tid, 1)
        self.assertEqual(self.kmc.business_key_at(tid, 2), self.terminals[0].device_keys()[1])
        import ctypes

        from grid_epoch.crypto import load

        root = os.urandom(32)
        frontier = TimeFrontier(root)
        self.assertEqual(frontier.advance_epoch(ERA), time_leaf(root, ERA))
        self.assertEqual(frontier.advance_epoch(ERA + 1), time_leaf(root, ERA + 1))
        lib = load()
        lib.ge_time_leaf.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        lib.ge_time_leaf.restype = ctypes.c_int
        out = (ctypes.c_uint8 * 32)()
        self.assertEqual(lib.ge_time_leaf(ctypes.create_string_buffer(root), ERA + 1, out), 0)
        self.assertEqual(bytes(out), time_leaf(root, ERA + 1))

    def test_transfer_rejects_the_old_leaf(self):
        self.activate()
        old = self.terminals[0]
        other = self.kmc.register_zone(43, 1)
        moved = self.kmc.transfer(old, 43, 1)
        self.assertNotEqual(moved.leaf, old.leaf)
        self.assertTrue(self.kmc.registry[old.tid].revoked)
        self.assertEqual(moved.device.public_key, old.device.public_key)
        release = self.kmc.publish(1)
        with self.assertRaises(TerminalRevoked):
            old.apply(release.terminal)
        other.sync(release.gateway)
        other.sync_revocation(release.revocation, self.kmc.proofs_for_zone(43))
        moved.apply(release.terminal)
        self.assertEqual(moved.device_keys(), self.kmc.device_keys(moved.tid))

    def test_slice_rejects_a_tampered_proof(self):
        release = self.kmc.publish(1)
        sliver = extract_for_leaf(release.terminal, self.kmc.cohorts[1].terminals.n, self.terminals[0].leaf)
        self.terminals[0].apply(sliver)
        self.assertEqual(self.terminals[0].epoch, 1)
        broken = bytearray(sliver)
        broken[-20] ^= 0x01
        with self.assertRaises(EpochRejected):
            self.terminals[1].apply(bytes(broken))
        watched = self.terminals[3]
        challenge = os.urandom(16)
        signature = watched.sign_enrollment(challenge)
        self.assertTrue(self.kmc.verify_enrollment(watched.tid, challenge, signature, watched.epoch))
        epoch_before = self.kmc.cohorts[1].epoch
        self.kmc.revoke(watched.tid)
        self.assertFalse(self.kmc.verify_enrollment(watched.tid, challenge, signature, watched.epoch))
        self.assertFalse(self.gateway.verify_enrollment(watched.tid, watched.tid & 0xFFFF, challenge, signature, watched.epoch))
        self.assertEqual(self.kmc.cohorts[1].epoch, epoch_before)
        release = self.kmc.publish(1)
        self.kmc.registry[watched.tid].revoked = False
        self.gateway.revoked_tids.discard(watched.tid)
        self.assertFalse(self.kmc.verify_enrollment(watched.tid, challenge, signature, watched.epoch))
        self.gateway.sync_revocation(release.revocation, self.kmc.proofs_for_zone(42))
        self.assertFalse(self.gateway.verify_enrollment(watched.tid, watched.tid & 0xFFFF, challenge, signature, watched.epoch))

    def test_administrative_cut_excludes_one_node(self):
        from grid_epoch.subtree import Subtree

        tree = Subtree(32, b"m" * 16, b"NODE", 8)
        self.assertEqual(tree.batch, 2)
        tree.revoke_span(0)
        kind, subsets = planned_cover(tree.n, set(tree.revoked), tree.batch)
        self.assertEqual(kind, "sd")
        self.assertEqual(len(subsets), 1)
        tree.revoke_county(0)
        kind, subsets = planned_cover(tree.n, set(tree.revoked), tree.batch)
        self.assertEqual(kind, "sd")
        self.assertEqual(len(subsets), 1)
        fresh = Subtree(32, b"m" * 16, b"NODE", 8)
        fresh.revoked.add(3)
        self.assertEqual(cover_choice(fresh.n, set(fresh.revoked), fresh.batch), "sd")
        fresh.revoke_batch(1, 0)
        self.assertEqual(cover_choice(fresh.n, set(fresh.revoked), fresh.batch), "sd")
        aligned = Subtree(32, b"m" * 16, b"NODE", 8)
        aligned.revoke_batch(1, 0)
        kind, subsets = planned_cover(aligned.n, set(aligned.revoked), aligned.batch)
        self.assertEqual(kind, "sd")
        self.assertEqual(len(subsets), 1)

    def test_city_node_does_not_carry_the_broadcast_root(self):
        from grid_epoch.derive import city_broadcast_key, city_slot_path, provincial_broadcast_root
        from grid_epoch.device import DeviceKey

        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16)
        kmc.create_cohort(2, 16)
        kmc.create_cohort(3, 16)
        root = provincial_broadcast_root(kmc.hsm._mk_mgmt)
        first = kmc.cities[1]
        second = kmc.cities[2]
        third = kmc.cities[3]
        self.assertEqual(first.broadcast, city_broadcast_key(kmc.hsm._mk_mgmt, city_slot_path(0)))
        self.assertEqual(second.broadcast, city_broadcast_key(kmc.hsm._mk_mgmt, city_slot_path(1)))
        self.assertEqual(third.broadcast, city_broadcast_key(kmc.hsm._mk_mgmt, city_slot_path(2)))
        self.assertEqual(len(city_slot_path(0)), 16)
        self.assertNotEqual(first.broadcast, root)
        self.assertNotIn(root, first.__dict__.values())
        self.assertNotIn(second.broadcast, first.__dict__.values())
        self.assertFalse(any(isinstance(value, DeviceKey) for value in first.__dict__.values()))
        kmc.register_zone(42, 1)
        kmc.register_zone(80, 2)
        gone = kmc.enroll(42, 1)
        kept = kmc.enroll(80, 1)
        kmc.revoke_cohort(1)
        with self.assertRaises(ProtocolError):
            kmc.publish(1)
        release = kmc.publish(2)
        kept.apply(release.terminal)
        with self.assertRaises(EpochRejected):
            gone.apply(release.terminal)

    def test_dlt_services_map_without_parsing_frames(self):
        from grid_epoch.services import GE01, GE03, service_for

        self.assertEqual(service_for("645", "读电能"), GE01)
        self.assertEqual(service_for("645", "读冻结"), GE01)
        self.assertEqual(service_for("698.45", "GET"), GE01)
        self.assertEqual(service_for("698.45", "REPORT"), GE01)
        self.assertEqual(service_for("645", "跳闸"), GE03)
        self.assertEqual(service_for("645", "对时"), GE03)
        self.assertEqual(service_for("698.45", "ACTION"), GE03)
        self.assertEqual(service_for("698.45", "设时钟"), GE03)


class ParallelUpdateTest(unittest.TestCase):
    def test_small_parallel_update_matches_python(self):
        mk_mgmt = os.urandom(32)
        mk_biz = os.urandom(32)
        cohort = 6
        width = county_zone_count(2)
        table = provision_table(mk_mgmt, mk_biz, 9, cohort, 1, 2, 2, width, 2)
        try:
            root = os.urandom(16)
            auth_nonce = os.urandom(16)
            biz_nonce = os.urandom(16)
            plain = struct.pack(">I", 3) + auth_nonce + biz_nonce
            sealed = seal(root, plain)
            xor_auth, xor_biz = parallel_update(table, root, sealed, 2)
        finally:
            free_table(table)
        acc_a = bytearray(16)
        acc_b = bytearray(16)
        managed = city_mgmt(mk_mgmt, cohort)
        business = city_biz(mk_biz, 9, cohort)
        for zone in range(1, 3):
            county = zone // width
            zk = zone_key(county_mgmt(managed, county), 9, zone)
            business_county = county_biz(business, county)
            for local in range(2):
                tid = make_tid(zone, local)
                ka = auth_key(time_leaf(seed_mgmt(zk, tid), 3), 3, auth_nonce)
                kb = biz_key(time_leaf(seed_biz(business_county, zone, tid), 3), 3, biz_nonce)
                for acc, block in ((acc_a, ka), (acc_b, kb)):
                    for i, value in enumerate(block):
                        acc[i] ^= value
        self.assertEqual(xor_auth, bytes(acc_a))
        self.assertEqual(xor_biz, bytes(acc_b))
        self.assertEqual(len(hmac_sm3(b"k", b"m")), 32)

    def test_stream_ack_matches_python(self):
        mk_biz = os.urandom(32)
        nonce = os.urandom(16)
        epoch = 4
        area, zone0, n_zones, per = 3, 8, 2, 3
        cohort = 2
        width = county_zone_count(n_zones)
        got = stream_ack(mk_biz, area, cohort, zone0, n_zones, per, width, epoch, nonce, 2)
        acc = bytearray(16)
        business = city_biz(mk_biz, area, cohort)
        for zone in range(zone0, zone0 + n_zones):
            business_county = county_biz(business, zone // width)
            for local in range(per):
                tid = make_tid(zone, local)
                leaf = time_leaf(seed_biz(business_county, zone, tid), epoch)
                for index, value in enumerate(completion_tag(leaf, zone, tid, epoch, nonce)):
                    acc[index] ^= value
        self.assertEqual(got, bytes(acc))
        self.assertNotEqual(got, bytes(16))


class DeskTest(unittest.TestCase):
    def test_registry_has_no_seeds_and_restore_needs_both_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            sink, offline = open_share_sink()
            desk = OperatorDesk(directory, sink=sink)
            desk.seal("甲", "乙")
            self.assertIsNone(desk.kmc._escrow_passwords)
            status = desk.publish("甲", "乙")
            self.assertIsNone(desk.kmc._escrow_passwords)
            self.assertFalse(hasattr(desk, "custodian"))
            self.assertFalse(hasattr(desk._sink, "get_masters"))
            self.assertFalse(hasattr(desk._sink, "directory"))
            encoded = json.dumps(status)
            self.assertNotIn(desk.kmc.hsm._mk_mgmt.hex(), encoded)
            self.assertNotIn(desk.kmc.hsm._mk_biz.hex(), encoded)
            self.assertNotIn(desk.kmc.hsm._sm9_master.hex(), encoded)
            self.assertTrue(status["packages"]["terminal"]["sm2"])
            self.assertNotIn("mldsa", status["packages"]["terminal"])
            self.assertEqual(desk.status()["cover"], "完全子树")
            confirmed = desk.confirm_zone(42)
            self.assertEqual(confirmed["count"], 4)
            self.assertFalse(confirmed["rejected"])
            self.assertEqual(confirmed["bytes"], ZALL_LEN)
            self.assertTrue(confirmed["audit_ok"])
            self.assertEqual(len(bytes.fromhex(confirmed["audit_root"])), 32)
            gateway = desk.kmc.gateways[42]
            tid = next(iter(gateway._completions))
            local, tag, signature = gateway._completions[tid]
            gateway._completions[tid] = (local, tag, signature[:-1] + bytes([signature[-1] ^ 1]))
            _root, still_ok = gateway.completion_audit()
            self.assertFalse(still_ok)
            self.assertEqual(desk.zones(0)["zones"][0]["acked"], 4)
            self.assertFalse(desk.zones(0)["zones"][0]["behind"])
            self.assertTrue(desk.zones(0)["zones"][1]["behind"])
            terminal = desk.terminals[(42, 0)]
            original = terminal.signed_completion

            def flipped():
                tag, signature = original()
                return tag, signature[:-1] + bytes([signature[-1] ^ 1])

            terminal.signed_completion = flipped
            try:
                blocked = desk.confirm_zone(42)
            finally:
                del terminal.signed_completion
            self.assertTrue(blocked["rejected"])
            self.assertFalse(blocked["audit_ok"])
            self.assertEqual(blocked["bytes"], ZALL_LEN)
            self.assertEqual(blocked["revoked"], 0)
            self.assertEqual(desk._open_revoked_count(42), 0)
            held = desk.confirm_zone(42, 1)
            self.assertTrue(held["rejected"])
            self.assertEqual(held["missing"], [1])
            self.assertEqual(held["count"], 3)
            self.assertEqual(held["revoked"], 0)
            self.assertEqual(desk.zones(0)["zones"][0]["acked"], 3)
            self.assertEqual(desk.zones(0)["zones"][0]["revoked"], 0)
            states = {row["local"]: row["state"] for row in desk.members(42)}
            self.assertEqual(states[1], "被扣下")
            self.assertEqual([states[local] for local in (0, 2, 3)], ["已确认", "已确认", "已确认"])
            desk.revoke(42, 1)
            self.assertEqual(desk.status()["cover"], "子集差")
            self.assertEqual({row["local"]: row["state"] for row in desk.members(42)}[1], "已吊销")
            from grid_epoch.console import load_bench
            bench = load_bench()
            self.assertEqual(
                set(bench),
                {"terminal", "gateway", "revocation", "confirm_bytes", "confirm_seconds"},
            )
            self.assertEqual(bench["confirm_bytes"], 62)
            with self.assertRaises(AuthFailed):
                restore_masters(
                    Path(directory, "share_a.bin").read_bytes(),
                    Path(directory, "share_b.bin").read_bytes(),
                    "甲",
                    "错",
                )
            desk.restore("甲", "乙")
            inspected = sqlite3.connect(Path(directory) / "registry.sqlite")
            try:
                columns = [row[1] for row in inspected.execute("PRAGMA table_info(terminal)")]
            finally:
                inspected.close()
            joined = " ".join(columns)
            self.assertNotIn("seed", joined)
            self.assertNotIn("sm9", joined)
            challenge = os.urandom(16)
            terminal = desk.terminals[(42, 0)]
            signature = terminal.sign_enrollment(challenge)
            self.assertTrue(desk.kmc.gateways[42].verify_enrollment(terminal.tid, 0, challenge, signature, terminal.epoch))
            self.assertFalse(desk.kmc.verify_enrollment(terminal.tid, challenge, signature, terminal.epoch + 1))
            epoch_before = desk.kmc.cohorts[1].epoch
            desk.check_enrollment(42, 0)
            self.assertEqual(desk.kmc.cohorts[1].epoch, epoch_before)
            desk.note_watch()
            self.assertEqual(desk.kmc.cohorts[1].epoch, epoch_before)
            self.assertFalse((Path(directory) / "nonce_1.bin").exists())
            self.assertFalse((Path(directory) / "share_offline.bin").exists())
            self.assertNotEqual(offline.resolve(), Path(directory).resolve())
            self.assertTrue((offline / "nonce_1.bin").is_file())
            self.assertTrue((offline / "share_offline.bin").is_file())
            nonce_share = (offline / "nonce_1.bin").read_bytes()
            third = (offline / "share_offline.bin").read_bytes()
            self.assertNotIn(nonce_share, desk.kmc.cohorts[1].escrow[1])
            with self.assertRaises(AuthFailed):
                desk.recover_epoch(1, "甲", "错")
            recovered = desk.recover_epoch(1, "甲", "乙")
            self.assertEqual(recovered, {"ok": True, "epoch": 1})
            self.assertNotIn(nonce_share.hex(), json.dumps(recovered))
            from grid_epoch.custody import restore_masters_offline
            from grid_epoch.sm9id import enrollment_id, enrollment_message, verify_message

            blob_a = (Path(directory) / "share_a.bin").read_bytes()
            self.assertEqual(
                restore_masters_offline(blob_a, "甲", third),
                (desk.kmc.hsm._mk_mgmt, desk.kmc.hsm._mk_biz, desk.kmc.hsm._sm9_master),
            )
            victim = desk.terminals[(42, 2)]
            challenge = os.urandom(16)
            kept = victim.sign_enrollment(challenge)
            record = desk.kmc.registry[victim.tid]
            held = victim.seal_telemetry(b"held")
            wrapped = desk.kmc.gateways[42].accept_and_wrap(held)
            fresh = victim.seal_telemetry(b"fresh")
            destroyed = desk.destroy_meter(42, 2)
            with self.assertRaises(TerminalRevoked) as province:
                desk.kmc.open_uplink(wrapped)
            self.assertEqual(str(province.exception), "终端已销毁")
            with self.assertRaises(TerminalRevoked) as gateway:
                desk.kmc.gateways[42].accept_and_wrap(fresh)
            self.assertEqual(str(gateway.exception), "终端已销毁")
            self.assertEqual(destroyed["destroyed"], True)
            self.assertFalse(desk.kmc.verify_enrollment(destroyed["tid"], challenge, kept, victim.epoch))
            self.assertFalse(
                desk.kmc.gateways[42].verify_enrollment(victim.tid, 2, challenge, kept, victim.epoch)
            )
            with self.assertRaises(ProtocolError) as wiped:
                victim.sign_enrollment(os.urandom(16))
            self.assertEqual(str(wiped.exception), "终端已销毁")
            desk.session.factory.send(f"PROOF 1 {os.urandom(16).hex()}")
            self.assertIn("产线没有这台终端", desk.session.factory.read())
            for action in (
                lambda: victim.apply(desk.release.terminal),
                lambda: victim.prove(os.urandom(16)),
                lambda: victim.seal_telemetry(b"x"),
                lambda: victim.ack(),
                lambda: victim.signed_completion(),
                lambda: victim.device_keys(),
            ):
                with self.assertRaises(ProtocolError) as caught:
                    action()
                self.assertEqual(str(caught.exception), "终端已销毁")
            self.assertTrue(
                verify_message(
                    desk.kmc.hsm.sm9_public,
                    enrollment_id(record.area, record.zone, record.local_index),
                    enrollment_message(challenge, victim.tid, victim.epoch),
                    kept,
                )
            )
            self.assertNotIn(record.leaf, desk.kmc.cohorts[1].terminals.revoked)
            self.assertFalse(record.revoked)
            city = desk.kmc.cities[1]
            slot = city.zone_index[43]
            cursor = city.cohort.terminals._cursor[slot]
            before = set(desk.kmc.registry)
            with self.assertRaises(ProtocolError) as blocked_move:
                desk.transfer_meter(42, 2, 43, 9)
            self.assertEqual(str(blocked_move.exception), "终端已销毁")
            self.assertEqual(set(desk.kmc.registry), before)
            self.assertEqual(city.cohort.terminals._cursor[slot], cursor)
            with self.assertRaises(ProtocolError) as blocked_fill:
                desk.reprovision(42, 2)
            self.assertEqual(str(blocked_fill.exception), "终端已销毁")
            zone42 = next(row for row in desk.zones(0)["zones"] if row["zone"] == 42)
            self.assertEqual(zone42["enrolled"], 2)
            self.assertEqual(zone42["destroyed"], 1)
            self.assertEqual(zone42["revoked"], 1)
            self.assertNotIn(record.leaf, desk.kmc.cohorts[1].terminals.revoked)
            source = desk.terminals[(42, 0)]
            source_tid = source.tid
            desk.transfer_meter(42, 0, 43, 5)
            desk.session.drop(source_tid)
            moved = desk.transfer_meter(43, 5, 44, 6)
            self.assertEqual(moved["zone"], 44)
            self.assertFalse(moved["destroyed"])
            desk.set_firmware(42, 2, 9)
            self.assertEqual(desk.recall_firmware(42, 9)["batches"], 1)
            replaced = desk.replace_meter(42, 1, 8)
            self.assertEqual(replaced["leaf"], 6)
            archived = desk.archive_audit(2)
            self.assertGreaterEqual(archived["moved"], 1)
            desk.session.city.send("NOPE")
            self.assertTrue(desk.session.city.read().startswith("FAIL ProtocolError"))
            desk.close()
            left, right, offline = seal_masters(b"m" * 32, b"b" * 32, b"s" * 32, "甲", "乙")
            self.assertEqual(restore_masters(left, right, "甲", "乙"), (b"m" * 32, b"b" * 32, b"s" * 32))
            from grid_epoch.custody import combine_shares, restore_masters_offline, split_secret

            secret = b"m" * 32 + b"b" * 32 + b"s" * 32
            shares = split_secret(secret)
            self.assertEqual(combine_shares(shares[0], shares[1]), secret)
            self.assertEqual(combine_shares(shares[0], shares[2]), secret)
            self.assertEqual(combine_shares(shares[2], shares[1]), secret)
            self.assertEqual(restore_masters_offline(left, "甲", offline), (b"m" * 32, b"b" * 32, b"s" * 32))


class EnrollmentTest(unittest.TestCase):
    def test_standard_sample_and_wrong_identity(self):
        from grid_epoch.sm9id import standard_sample_verifies

        self.assertTrue(standard_sample_verifies())


class CollaborativeSignTest(unittest.TestCase):
    def test_either_share_alone_fails_the_published_key(self):
        signer = CollaborativeSM2()
        other = CollaborativeSM2()
        try:
            message = b"epoch-body"
            signature = signer.sign(message)
            self.assertTrue(signer.verify(message, signature))
            self.assertNotIn("private_key", signer.__dict__)
            self.assertNotIn("_d2", signer.client.__dict__)
            self.assertFalse(signer.verify(message, other.sign(message)))
            signer.client = ClientShare(1, signer.client.w1)
            with self.assertRaises(RuntimeError):
                signer.sign(message)
        finally:
            signer.close()
            other.close()


class BoundaryTest(unittest.TestCase):
    def test_county_key_and_sm9_stay_off_the_city(self):
        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16)
        kmc.register_zone(42, 1)
        kmc.register_zone(43, 1)
        city = kmc.cities[1]
        left = city.county_for(42)
        right = city.county_for(43)
        zones = city.cohort.terminals.n // city.cohort.span
        self.assertEqual(city.county_index_of(42), county_index(0, zones))
        self.assertEqual(city.county_index_of(42), 0)
        self.assertNotEqual(city.county_index_of(42), 42 // county_zone_count(zones))
        self.assertNotEqual(left.county_index, right.county_index)
        self.assertNotEqual(left.county_mgmt, right.county_mgmt)
        self.assertNotIn(city.city_mgmt, left.__dict__.values())
        self.assertNotIn(city.city_biz, left.__dict__.values())
        self.assertNotIn(kmc.hsm.broadcast_root(), left.__dict__.values())
        terminal = kmc.enroll(42, 0)
        self.assertFalse(_contains(city, terminal.sm9_user))
        self.assertNotIn(city.broadcast, terminal.path_keys.values())
        self.assertEqual(terminal.path_keys[1], cs_open_key(city.broadcast))
        self.assertEqual(terminal.path_keys[left.node_id], left.broadcast)
        below = left.node_id * 2
        self.assertEqual(terminal.path_keys[below], descend_from(left.broadcast, left.node_id, below))
        original = left.broadcast
        left.broadcast = bytes(byte ^ 0x01 for byte in original)
        self.assertNotEqual(left.node_key(below), terminal.path_keys[below])
        left.broadcast = original
        release = kmc.publish(1)
        parsed = parse_terminal_package(release.terminal)
        self.assertEqual(parsed.cover, "cs")
        self.assertEqual(list(parsed.entries), [1])
        terminal.apply(release.terminal)
        self.assertEqual(terminal.epoch, 1)

    def test_leaf_quota_and_disjoint_firmware_batches(self):
        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16, leaf_quota=1)
        kmc.register_zone(42, 1)
        first = kmc.enroll(42, 0)
        self.assertEqual(first.leaf, 0)
        with self.assertRaises(ProtocolError) as caught:
            kmc.enroll(42, 1)
        self.assertEqual(str(caught.exception), "叶子越界")

        other = ProvincialKMC(area=330100)
        other.arm_escrow("甲", "乙")
        other.create_cohort(1, 16)
        other.register_zone(42, 1)
        other.register_zone(43, 1)
        other.set_firmware(42, 0, 7)
        other.set_firmware(43, 0, 7)
        self.assertEqual(other.recall_firmware(42, 7), 1)
        self.assertEqual(other.recall_firmware(43, 7), 1)
        kind, subsets = planned_cover(
            other.cohorts[1].terminals.n,
            set(other.cohorts[1].terminals.revoked),
            other.cohorts[1].terminals.batch,
        )
        self.assertEqual(kind, "sd")
        self.assertEqual(len(subsets), 2)
        covered = set()
        for subset in subsets:
            covered |= live_leaves(other.cohorts[1].terminals.n, subset)
        self.assertTrue(set(range(0, 2)).isdisjoint(covered))
        self.assertTrue(set(range(8, 10)).isdisjoint(covered))
        self.assertIn(2, covered)

        same = ProvincialKMC(area=330100)
        same.arm_escrow("甲", "乙")
        same.create_cohort(1, 16)
        same.register_zone(42, 1)
        same.set_firmware(42, 0, 7)
        same.set_firmware(42, 2, 7)
        self.assertEqual(same.recall_firmware(42, 7), 2)
        kind, subsets = planned_cover(
            same.cohorts[1].terminals.n,
            set(same.cohorts[1].terminals.revoked),
            same.cohorts[1].terminals.batch,
        )
        self.assertEqual(kind, "sd")
        self.assertEqual(subsets, [(4, 8), (5, 10), (1, 2)])

    def test_bad_delegation_and_firmware_batch_and_zone_forward(self):
        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16)
        kmc.register_zone(42, 1)
        kmc.register_zone(43, 1)
        home = [kmc.enroll(42, index) for index in range(2)]
        neighbor = kmc.enroll(43, 0)
        city = kmc.cities[1]
        broken = bytearray(city.token)
        broken[-1] ^= 0x01
        city.token = bytes(broken)
        with self.assertRaises(ProtocolError):
            kmc.publish(1)
        city.token = bytes(broken[:-1]) + bytes([broken[-1] ^ 0x01])
        kmc.recall_firmware_batch(42, 0)
        kind, count = kmc.recall_plan(1)
        self.assertEqual((kind, count), ("sd", 1))
        release = kmc.publish(1)
        forwarded = kmc.forward_zone(43, release.terminal)
        self.assertEqual(len(forwarded), 1)
        neighbor.apply(forwarded[0])
        self.assertEqual(neighbor.epoch, 1)
        with self.assertRaises(TerminalRevoked):
            home[0].apply(release.terminal)

    def test_escrow_archive_destroy_and_auth_frontier(self):
        from grid_epoch.auditproof import audit_root, sign_completion, verify_completion_audit
        from grid_epoch.custody import open_epoch_nonces

        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16)
        kmc.register_zone(42, 1)
        terminal = kmc.enroll(42, 0)
        first = kmc.publish(1)
        terminal.apply(first.terminal)
        saved_auth = terminal.auth_nonce
        saved_key = terminal.device_keys()[0]
        old_leaf = time_leaf(terminal.seed_mgmt, 1)
        live_auth = kmc.cohorts[1].current_auth()
        live_biz = kmc.cohorts[1].current_biz()
        second = kmc.publish(1)
        terminal.apply(second.terminal)
        stored = [bytes(key) for _start, _span, key in terminal.auth_frontier.nodes]
        self.assertNotIn(old_leaf, stored)
        self.assertNotEqual(terminal.device_keys()[0], saved_key)
        seed_m, _seed_b = kmc._seeds(kmc.registry[terminal.tid])
        self.assertEqual(auth_key(time_leaf(seed_m, 1), 1, saved_auth), saved_key)
        kmc.drop_expired(1, 2)
        with self.assertRaises(EpochRejected):
            kmc.business_key_at(terminal.tid, 1)
        self.assertEqual(kmc.recover_nonces(1, 1, "甲", "乙"), (live_auth, live_biz))
        with self.assertRaises(AuthFailed):
            open_epoch_nonces(*kmc.cohorts[1].escrow[1], "甲", "错")
        tag, signature = sign_completion(terminal)
        root = audit_root([(terminal.tid, tag, signature)])
        self.assertTrue(
            verify_completion_audit(
                kmc.hsm.sm9_public,
                330100,
                42,
                terminal.epoch,
                [(terminal.tid & 0xFFFF, terminal.tid, tag, signature)],
                root,
            )
        )
        self.assertFalse(
            verify_completion_audit(
                kmc.hsm.sm9_public,
                330100,
                42,
                terminal.epoch,
                [(terminal.tid & 0xFFFF, terminal.tid, tag, signature[:-1] + bytes([signature[-1] ^ 1]))],
                root,
            )
        )
        self.assertFalse(hasattr(kmc.gateways[42], "sm9_user"))
        with tempfile.TemporaryDirectory() as directory:
            desk = OperatorDesk(directory)
            desk.store.audit("较早", "留档")
            desk.store.audit("较新", "热表")
            self.assertEqual(desk.store.archive_before(2), 1)
            self.assertEqual(desk.store.archived_audit()[0]["action"], "较早")
            self.assertTrue(all(row["id"] >= 2 for row in desk.store.recent_audit(10)))
            watched = desk.terminals[(42, 0)]
            leaf = watched.leaf
            desk.kmc.destroy_record(watched.tid)
            desk.store.destroy_terminal(watched.tid)
            desk._mirror(watched.tid)
            row = desk.store.find_terminal(42, 0)
            self.assertEqual(row["leaf"], leaf)
            self.assertEqual(row["destroyed"], 1)
            desk.seal("甲", "乙")
            desk.publish("甲", "乙")
            self.assertIsNone(desk.kmc._escrow_passwords)
            self.assertFalse(desk.kmc.verify_enrollment(watched.tid, os.urandom(16), b"\x00" * 64, 1))
            desk.close()

    def test_city_and_factory_are_separate_processes(self):
        import subprocess
        import sys

        kmc = ProvincialKMC(area=330100)
        kmc.create_cohort(9, 16)
        city = kmc.cities[9]
        init = " ".join(
            [
                "INIT",
                str(city.area),
                str(city.cohort_id),
                str(city.slot),
                str(city.cohort.terminals.n),
                str(city.cohort.span),
                city.city_mgmt.hex(),
                city.city_biz.hex(),
                city.broadcast.hex(),
                city.token.hex(),
                city.verify_key,
                kmc.hsm.sm9_public.hex(),
            ]
        )
        self.assertNotIn(kmc.hsm._mk_mgmt.hex(), init)
        self.assertNotIn(kmc.hsm._mk_biz.hex(), init)
        server = subprocess.Popen(
            [sys.executable, "-m", "grid_epoch.city_server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        factory = subprocess.Popen(
            [sys.executable, "-m", "grid_epoch.factory"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            server.stdin.write(init + "\n")
            server.stdin.flush()
            self.assertEqual(server.stdout.readline().strip(), "READY")
            server.stdin.write("REGISTER 42\n")
            server.stdin.flush()
            self.assertEqual(server.stdout.readline().strip(), "OK")
            factory.stdin.write("NEW\n")
            factory.stdin.flush()
            kind, public = factory.stdout.readline().strip().split()
            self.assertEqual(kind, "PUB")
            server.stdin.write(f"PROVISION 42 0 {public}\n")
            server.stdin.flush()
            blob_line = server.stdout.readline().strip().split()
            meta_line = server.stdout.readline().strip().split()
            self.assertEqual(blob_line[0], "BLOB")
            self.assertEqual(meta_line[0], "META")
            self.assertNotIn(kmc.hsm._mk_mgmt.hex(), blob_line[1])
            identity = kmc.hsm.seal_user_key(public, 330100, 42, 0)
            nonce = "00" * 16
            factory.stdin.write(
                "OPEN"
                f" {public} {blob_line[1]} {identity.hex()}"
                f" 330100 42 {meta_line[2]} {meta_line[1]} 9 0 0 16 {nonce} {nonce} {kmc.hsm.public_key}\n"
            )
            factory.stdin.flush()
            self.assertTrue(factory.stdout.readline().strip().startswith("OPEN "))
        finally:
            if server.poll() is None:
                server.stdin.write("QUIT\n")
                server.stdin.flush()
            if factory.poll() is None:
                factory.stdin.write("QUIT\n")
                factory.stdin.flush()
            server.wait(timeout=10)
            factory.wait(timeout=10)
            server.stdin.close()
            server.stdout.close()
            factory.stdin.close()
            factory.stdout.close()


def _contains(obj, needle: bytes, seen: set | None = None) -> bool:
    if seen is None:
        seen = set()
    mark = id(obj)
    if mark in seen:
        return False
    seen.add(mark)
    if isinstance(obj, (bytes, bytearray)) and needle in bytes(obj):
        return True
    if isinstance(obj, dict):
        return any(_contains(value, needle, seen) for value in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return any(_contains(value, needle, seen) for value in obj)
    if hasattr(obj, "__dict__"):
        return _contains(vars(obj), needle, seen)
    return False


class SceneTimelineTest(unittest.TestCase):
    def test_steps_follow_one_timeline(self):
        from grid_epoch.scenes import STEPS, Story

        story = Story()
        try:
            done = {}
            for name, fn in STEPS:
                done[name] = fn(story)
        finally:
            story.close()
        self.assertTrue(done["epoch0"]["rejected"])
        self.assertTrue(done["energy"]["business_rejected"])
        self.assertTrue(done["energy"]["opened"])
        self.assertTrue(done["control"]["gateway_opened"])
        self.assertTrue(done["control"]["station_opened"])
        self.assertEqual(done["jump"]["entered"], 2)
        self.assertTrue(done["jump"]["old_rejected"])
        self.assertEqual(done["publish"]["left_behind"], 0)
        self.assertEqual(done["drop"]["epoch"], 2)
        self.assertTrue(done["drop"]["epoch1_blocked"])
        self.assertEqual(done["withhold"]["revoked"], 0)
        self.assertEqual(done["withhold"]["missing_local"], 1)
        self.assertEqual(done["confirm"]["bytes"], 62)
        self.assertFalse(done["revoke"]["opened"])
        self.assertEqual(done["revoke"]["cover"], "sd")
        self.assertEqual(done["replace"]["local"], 4)
        self.assertTrue(done["replace"]["path_same"])
        self.assertEqual(story.terminals[4].epoch, done["replace"]["epoch"])
        self.assertFalse(done["destroy"]["in_revoked"])
        self.assertTrue(done["reject-enroll"]["rejected"])
        self.assertTrue(done["reject-transfer"]["rejected"])
        self.assertTrue(done["reject-reprovision"]["rejected"])
        self.assertFalse(done["gateway"]["rotated"])
        self.assertEqual(done["recall"]["cover"], "sd")


if __name__ == "__main__":
    unittest.main()
