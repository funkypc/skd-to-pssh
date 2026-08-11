import base64
import re
import struct

WIDEVINE_SYSTEM_ID = bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")
PSSH_SUFFIX = bytes.fromhex("48f3c6899b06") #cbcs (AES-CBC, pattern)


def get_kid(skd):
    """Build KID from skd"""
    skd = skd.strip()
    if "skd://" in skd:
        skd = skd[skd.index("skd://"):]
    skd = skd.strip('"').strip("'")
    match = re.match(r"skd://[^/]+/p(\d+)/([0-9a-z]+)", skd, re.IGNORECASE)
    if not match:
        raise ValueError(f"invalid skd: {skd}")
    content_id = match.group(1)
    track = match.group(2)
    return (
        "00000000"
        + format(int(content_id), "08x")
        + track.encode().hex()
        + "202020202020"
    )


def get_pssh(kid):
    """Build the Widevine PSSH box containing the KID."""
    kid_bytes = bytes.fromhex(kid)
    data = b"\x12\x10" + kid_bytes + PSSH_SUFFIX
    box = (
        struct.pack(">I", 12 + 16 + 4 + len(data))
        + b"pssh"
        + struct.pack(">I", 0)
        + WIDEVINE_SYSTEM_ID
        + struct.pack(">I", len(data))
        + data
    )
    return base64.b64encode(box).decode()


def get_pssh_pr(kid):
    """Build the PlayReady object with the GUID-form KID."""
    kid_bytes = bytes.fromhex(kid)
    guid_kid = kid_bytes[0:4][::-1] + kid_bytes[4:6][::-1] + kid_bytes[6:8][::-1] + kid_bytes[8:16]
    value = base64.b64encode(guid_kid).decode()
    xml = (
        '<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" '
        'version="4.3.0.0"><DATA><PROTECTINFO><KIDS><KID ALGID="AESCBC" '
        f'VALUE="{value}"></KID></KIDS></PROTECTINFO></DATA></WRMHEADER>'
    )
    xml_bytes = xml.encode("utf-16-le")
    payload = (
        struct.pack("<IHH", 10 + len(xml_bytes), 1, 1)
        + struct.pack("<H", len(xml_bytes))
        + xml_bytes
    )
    return base64.b64encode(payload).decode()


def main():
    skd = input("skd: ")
    kid = get_kid(skd)
    print("KID:", kid)
    print("PSSH:", get_pssh(kid))
    print("PSSH_PR:", get_pssh_pr(kid))


if __name__ == "__main__":
    main()
