#!/usr/bin/env python3
"""Export real libnm in-memory normalization; never construct NM.Client or a bus.

new_from_dbus normalizes a SimpleConnection in memory. This is client-library
serialization evidence, not a NetworkManager daemon or gateway acceptance test.
The input has no credentials, addresses or real-world identifiers.
"""

import argparse
import json
import os
from pathlib import Path

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402


def typed_settings(value):
    """Keep each actual inner GVariant signature, including empty containers."""
    if value.get_type_string() != "a{sa{sv}}":
        raise ValueError("unexpected libnm settings signature")
    result = {}
    for index in range(value.n_children()):
        entry = value.get_child_value(index)
        section = entry.get_child_value(0).get_string()
        values = entry.get_child_value(1)
        result[section] = {}
        for item_index in range(values.n_children()):
            item = values.get_child_value(item_index)
            key = item.get_child_value(0).get_string()
            variant = item.get_child_value(1).get_variant()
            result[section][key] = {
                "signature": variant.get_type_string(),
                "value": variant.unpack(),
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if os.environ.get("MERIDIAN_NMVPN_WIRE_TESTS") != "1":
        raise SystemExit("explicit disposable-fixture opt-in required")
    for key in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS",
                "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE"):
        if key in os.environ:
            raise SystemExit("inherited bus address is forbidden")
    settings = {
        "connection": {
            "id": GLib.Variant("s", "Meridian normalization fixture"),
            "uuid": GLib.Variant("s", "12345678-1234-1234-1234-123456789abc"),
            "type": GLib.Variant("s", "vpn"),
            "autoconnect": GLib.Variant("b", False),
        },
        "vpn": {
            "service-type": GLib.Variant("s", "org.freedesktop.NetworkManager.meridian"),
        },
        "ipv4": {
            "method": GLib.Variant("s", "auto"),
            "never-default": GLib.Variant("b", True),
            "ignore-auto-dns": GLib.Variant("b", True),
        },
        "ipv6": {"method": GLib.Variant("s", "disabled")},
    }
    original = GLib.Variant("a{sa{sv}}", settings)
    connection = NM.SimpleConnection.new_from_dbus(original)
    if connection is None or not connection.verify():
        raise SystemExit("in-memory libnm connection did not verify")
    normalized = connection.to_dbus(NM.ConnectionSerializationFlags.ALL)
    result = {
        "version": 1,
        "libnmVersion": f"{NM.MAJOR_VERSION}.{NM.MINOR_VERSION}.{NM.MICRO_VERSION}",
        "source": "NM.SimpleConnection.new_from_dbus / to_dbus(ALL), no daemon",
        "input": typed_settings(original),
        "normalized": typed_settings(normalized),
    }
    data = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if len(data.encode()) > 65536:
        raise SystemExit("unexpectedly large normalization fixture")
    args.output.write_text(data)
    print(f"Verified in-memory libnm {result['libnmVersion']} serialization")


if __name__ == "__main__":
    main()
