#!/usr/bin/env python3
"""Apply WinST/DT anti-evasion libvirt settings to a domain XML file."""

from __future__ import annotations

import argparse
import hashlib
import os
import uuid
import xml.etree.ElementTree as ET


LIBOSINFO_NS = "http://libosinfo.org/xmlns/libvirt/domain/1.0"
QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
ET.register_namespace("libosinfo", LIBOSINFO_NS)
ET.register_namespace("qemu", QEMU_NS)


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def child(parent: ET.Element, tag: str) -> ET.Element | None:
    return parent.find(tag)


def ensure_child(parent: ET.Element, tag: str, **attrs: str) -> ET.Element:
    item = child(parent, tag)
    if item is None:
        item = ET.SubElement(parent, tag)
    for key, value in attrs.items():
        item.set(key, value)
    return item


def set_entry(section: ET.Element, name: str, value: str) -> None:
    for entry in section.findall("entry"):
        if entry.get("name") == name:
            entry.text = value
            return
    entry = ET.SubElement(section, "entry", {"name": name})
    entry.text = value


def deterministic_serial(domain_name: str, prefix: str, length: int) -> str:
    digest = hashlib.sha256(domain_name.encode("utf-8")).hexdigest().upper()
    return (prefix + digest)[:length]


def deterministic_uuid(domain_name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"winstdt.local/{domain_name}"))


def insert_after(root: ET.Element, new_child: ET.Element, after_tags: tuple[str, ...]) -> None:
    existing = child(root, new_child.tag)
    if existing is not None:
        root.remove(existing)
    children = list(root)
    insert_at = 0
    for index, item in enumerate(children):
        if item.tag in after_tags:
            insert_at = index + 1
    root.insert(insert_at, new_child)


def build_sysinfo(domain_name: str, domain_uuid: str) -> ET.Element:
    system_serial = env("WINSTDT_SMBIOS_SYSTEM_SERIAL", deterministic_serial(domain_name, "DL", 14))
    board_serial = env("WINSTDT_SMBIOS_BOARD_SERIAL", deterministic_serial(domain_name, "BRD", 14))
    chassis_serial = env("WINSTDT_SMBIOS_CHASSIS_SERIAL", deterministic_serial(domain_name, "CHS", 14))

    sysinfo = ET.Element("sysinfo", {"type": "smbios"})
    bios = ET.SubElement(sysinfo, "bios")
    set_entry(bios, "vendor", env("WINSTDT_SMBIOS_BIOS_VENDOR", "Dell Inc."))
    set_entry(bios, "version", env("WINSTDT_SMBIOS_BIOS_VERSION", "1.18.0"))
    set_entry(bios, "date", env("WINSTDT_SMBIOS_BIOS_DATE", "09/12/2023"))
    set_entry(bios, "release", env("WINSTDT_SMBIOS_BIOS_RELEASE", "1.18"))

    system = ET.SubElement(sysinfo, "system")
    set_entry(system, "manufacturer", env("WINSTDT_SMBIOS_SYSTEM_MANUFACTURER", "Dell Inc."))
    set_entry(system, "product", env("WINSTDT_SMBIOS_SYSTEM_PRODUCT", "Latitude 5540"))
    set_entry(system, "version", env("WINSTDT_SMBIOS_SYSTEM_VERSION", "1.0"))
    set_entry(system, "serial", system_serial)
    set_entry(system, "uuid", env("WINSTDT_SMBIOS_SYSTEM_UUID", domain_uuid or deterministic_uuid(domain_name)))
    set_entry(system, "sku", env("WINSTDT_SMBIOS_SYSTEM_SKU", "0B19"))
    set_entry(system, "family", env("WINSTDT_SMBIOS_SYSTEM_FAMILY", "Latitude"))

    base_board = ET.SubElement(sysinfo, "baseBoard")
    set_entry(base_board, "manufacturer", env("WINSTDT_SMBIOS_BOARD_MANUFACTURER", "Dell Inc."))
    set_entry(base_board, "product", env("WINSTDT_SMBIOS_BOARD_PRODUCT", "0M6C7G"))
    set_entry(base_board, "version", env("WINSTDT_SMBIOS_BOARD_VERSION", "A00"))
    set_entry(base_board, "serial", board_serial)

    chassis = ET.SubElement(sysinfo, "chassis")
    set_entry(chassis, "manufacturer", env("WINSTDT_SMBIOS_CHASSIS_MANUFACTURER", "Dell Inc."))
    set_entry(chassis, "version", env("WINSTDT_SMBIOS_CHASSIS_VERSION", "1.0"))
    set_entry(chassis, "serial", chassis_serial)
    set_entry(chassis, "asset", env("WINSTDT_SMBIOS_CHASSIS_ASSET", deterministic_serial(domain_name, "ASSET", 12)))
    set_entry(chassis, "sku", env("WINSTDT_SMBIOS_CHASSIS_SKU", "Notebook"))
    return sysinfo


def harden_os(root: ET.Element) -> None:
    os_elem = ensure_child(root, "os")
    ensure_child(os_elem, "smbios", mode="sysinfo")


def harden_features(root: ET.Element, hyperv_vendor: str) -> None:
    features = ensure_child(root, "features")
    kvm = ensure_child(features, "kvm")
    ensure_child(kvm, "hidden", state="on")

    hyperv = child(features, "hyperv")
    if hyperv is not None:
        ensure_child(hyperv, "vendor_id", state="on", value=hyperv_vendor[:12])


def harden_cpu(root: ET.Element, cpus: int) -> None:
    vcpu = ensure_child(root, "vcpu", placement="static")
    vcpu.text = str(cpus)
    cpu = child(root, "cpu")
    if cpu is None:
        cpu = ET.Element("cpu", {"mode": "host-passthrough", "check": "none", "migratable": "on"})
        features = child(root, "features")
        root.insert(list(root).index(features) + 1 if features is not None else 0, cpu)
    else:
        cpu.set("mode", env("WINSTDT_CPU_MODE", cpu.get("mode", "host-passthrough")))
        cpu.set("check", env("WINSTDT_CPU_CHECK", cpu.get("check", "none")))
    ensure_child(cpu, "topology", sockets="1", dies="1", cores=str(cpus), threads="1")


def harden_disks(root: ET.Element, domain_name: str) -> None:
    devices = child(root, "devices")
    if devices is None:
        return
    for index, disk in enumerate(devices.findall("disk"), start=1):
        if disk.get("device") != "disk":
            continue
        alias = child(disk, "alias")
        if alias is None:
            alias = ET.SubElement(disk, "alias")
        alias.set("name", f"ua-winst-disk{index}")

        serial = child(disk, "serial")
        if serial is None:
            serial = ET.SubElement(disk, "serial")
        serial.text = env("WINSTDT_DISK_SERIAL", deterministic_serial(f"{domain_name}-{index}", "WD", 18))

        target = child(disk, "target")
        target_bus = target.get("bus") if target is not None else ""
        existing_wwn = child(disk, "wwn")
        if target_bus in {"ide", "scsi"}:
            wwn = existing_wwn if existing_wwn is not None else ET.SubElement(disk, "wwn")
            wwn.text = env("WINSTDT_DISK_WWN", hashlib.sha1(f"{domain_name}-{index}".encode()).hexdigest()[:16])
        elif existing_wwn is not None:
            disk.remove(existing_wwn)

    for balloon in list(devices.findall("memballoon")):
        balloon.clear()
        balloon.set("model", "none")


def has_qemu_arg(commandline: ET.Element, value: str) -> bool:
    return any(arg.get("value") == value for arg in commandline.findall(f"{{{QEMU_NS}}}arg"))


def append_qemu_arg_pair(commandline: ET.Element, first: str, second: str) -> None:
    args = commandline.findall(f"{{{QEMU_NS}}}arg")
    for index, arg in enumerate(args[:-1]):
        if arg.get("value") == first and args[index + 1].get("value") == second:
            return
    ET.SubElement(commandline, f"{{{QEMU_NS}}}arg", {"value": first})
    ET.SubElement(commandline, f"{{{QEMU_NS}}}arg", {"value": second})


def remove_qemu_arg_pair_prefix(commandline: ET.Element, first: str, second_prefix: str) -> None:
    args = list(commandline.findall(f"{{{QEMU_NS}}}arg"))
    index = 0
    while index < len(args) - 1:
        if args[index].get("value") == first and (args[index + 1].get("value") or "").startswith(second_prefix):
            commandline.remove(args[index])
            commandline.remove(args[index + 1])
            args = list(commandline.findall(f"{{{QEMU_NS}}}arg"))
            continue
        index += 1


def harden_qemu_commandline(root: ET.Element) -> None:
    commandline = root.find(f"{{{QEMU_NS}}}commandline")
    if commandline is None:
        commandline = ET.Element(f"{{{QEMU_NS}}}commandline")
        root.append(commandline)

    oem_id = env("WINSTDT_ACPI_OEM_ID", "DELL")[:6]
    oem_table_id = env("WINSTDT_ACPI_OEM_TABLE_ID", "CBX3")[:8]
    append_qemu_arg_pair(commandline, "-machine", f"x-oem-id={oem_id},x-oem-table-id={oem_table_id}")

    if env("WINSTDT_ENABLE_QEMU_DISK_MODEL_SET", "0") == "1":
        disk_model = env("WINSTDT_DISK_MODEL", "WDC WD5000LPCX-75VHAT0")
        append_qemu_arg_pair(commandline, "-set", f"device.sata0-0-0.model={disk_model}")
    else:
        remove_qemu_arg_pair_prefix(commandline, "-set", "device.sata0-0-0.model=")


def harden_qemu_overrides(root: ET.Element) -> None:
    override = root.find(f"{{{QEMU_NS}}}override")
    if override is None:
        override = ET.Element(f"{{{QEMU_NS}}}override")
        root.append(override)

    disk_model = env("WINSTDT_DISK_MODEL", "WDC WD5000LPCX-75VHAT0")
    disk_alias = "ua-winst-disk1"
    device = None
    for candidate in override.findall(f"{{{QEMU_NS}}}device"):
        if candidate.get("alias") == disk_alias:
            device = candidate
            break
    if device is None:
        device = ET.SubElement(override, f"{{{QEMU_NS}}}device", {"alias": disk_alias})
    frontend = device.find(f"{{{QEMU_NS}}}frontend")
    if frontend is None:
        frontend = ET.SubElement(device, f"{{{QEMU_NS}}}frontend")

    for prop in list(frontend.findall(f"{{{QEMU_NS}}}property")):
        if prop.get("name") in {"model", "rotation_rate"}:
            frontend.remove(prop)
    ET.SubElement(frontend, f"{{{QEMU_NS}}}property", {"name": "model", "type": "string", "value": disk_model})
    ET.SubElement(frontend, f"{{{QEMU_NS}}}property", {"name": "rotation_rate", "type": "unsigned", "value": "5400"})


def remove_runtime_only_fields(root: ET.Element) -> None:
    root.attrib.pop("id", None)
    for tag in ("seclabel",):
        for item in list(root.findall(tag)):
            root.remove(item)
    devices = child(root, "devices")
    if devices is not None:
        for xpath in ("./*/alias", "./*/address"):
            for item in devices.findall(xpath):
                parent = next((candidate for candidate in devices.iter() if item in list(candidate)), None)
                if parent is not None:
                    parent.remove(item)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cpus", type=int, default=int(env("VM_CPUS", "4")))
    parser.add_argument("--hyperv-vendor", default=env("WINSTDT_HYPERV_VENDOR_ID", "DellInc2023"))
    args = parser.parse_args()

    tree = ET.parse(args.input)
    root = tree.getroot()
    domain_name = child(root, "name").text if child(root, "name") is not None else "winstdt-win10-22h2"

    remove_runtime_only_fields(root)
    domain_uuid = child(root, "uuid").text if child(root, "uuid") is not None else ""

    insert_after(root, build_sysinfo(domain_name, domain_uuid), ("name", "uuid"))
    harden_os(root)
    harden_features(root, args.hyperv_vendor)
    harden_cpu(root, args.cpus)
    harden_disks(root, domain_name)
    harden_qemu_commandline(root)
    harden_qemu_overrides(root)

    ET.indent(tree, space="  ")
    tree.write(args.output, encoding="unicode", xml_declaration=False)
    with open(args.output, "a", encoding="utf-8") as handle:
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
