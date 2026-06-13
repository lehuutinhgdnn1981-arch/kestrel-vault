# Kestrel Vault - Tauri Icon Generator
# Cach dung: python generate_tauri_icons.py <duong_dan_anh_goc>
# Vi du: python generate_tauri_icons.py "C:/Users/SongPhatComputer/Downloads/Logo.png"
# Output: E:/Projectnew/kestrel-vault-source/src-tauri/icons/
# Yeu cau: pip install Pillow

import sys
import os
import struct
import io
from pathlib import Path
from PIL import Image

# === CAU HINH ===
OUTPUT_DIR = Path(r"E:\Projectnew\kestrel-vault-source\src-tauri\icons")

# Cac size can tao cho Tauri v2
REQUIRED_SIZES = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}


def resize_with_padding(img, size):
    """Resize anh giu nguyen ti le, them padding transparent neu can."""
    img = img.convert("RGBA")
    w, h = img.size
    ratio = min(size / w, size / h)
    new_w = int(w * ratio)
    new_h = int(h * ratio)
    resized = img.resize((new_w, new_h), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset_x = (size - new_w) // 2
    offset_y = (size - new_h) // 2
    canvas.paste(resized, (offset_x, offset_y), resized)
    return canvas


def png_bytes(img):
    """Lay PNG bytes tu PIL Image."""
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def create_ico(images_dict, output_path):
    """Tao file ICO tu dict {size: PIL_Image}, dung PNG-based entries."""
    sorted_sizes = sorted(images_dict.keys())
    entries = []
    for size in sorted_sizes:
        img = images_dict[size].convert("RGBA")
        data = png_bytes(img)
        entries.append({
            "width": size if size < 256 else 0,
            "height": size if size < 256 else 0,
            "png_data": data,
        })

    num_images = len(entries)
    ico_header = struct.pack("<HHH", 0, 1, num_images)
    header_size = 6 + (num_images * 16)
    data_blobs = []
    current_offset = header_size
    dir_entries = []

    for entry in entries:
        png_len = len(entry["png_data"])
        dir_entry = struct.pack(
            "<BBBBHHII",
            entry["width"],
            entry["height"],
            0, 0, 1, 32,
            png_len,
            current_offset,
        )
        dir_entries.append(dir_entry)
        data_blobs.append(entry["png_data"])
        current_offset += png_len

    with open(output_path, "wb") as f:
        f.write(ico_header)
        for de in dir_entries:
            f.write(de)
        for blob in data_blobs:
            f.write(blob)

    print(f"  + icon.ico ({num_images} sizes, {os.path.getsize(output_path):,} bytes)")


def create_icns(images_dict, output_path):
    """Tao file ICNS (macOS icon), dung PNG-based icon type."""
    size_to_code = {
        16: b"icp4",
        32: b"icp4",
        64: b"icp5",
        128: b"icp5",
        256: b"ic07",
        512: b"ic09",
    }

    chunks = []
    for size, img in sorted(images_dict.items()):
        code = size_to_code.get(size, b"icp5")
        png_data = png_bytes(img)
        chunk_length = 8 + len(png_data)
        chunk = code + struct.pack(">I", chunk_length) + png_data
        chunks.append(chunk)

    total_length = 8 + sum(len(c) for c in chunks)
    icns_data = b"icns" + struct.pack(">I", total_length)
    for chunk in chunks:
        icns_data += chunk

    with open(output_path, "wb") as f:
        f.write(icns_data)

    print(f"  + icon.icns ({len(chunks)} sizes, {os.path.getsize(output_path):,} bytes)")


def main():
    print("=" * 55)
    print("  Kestrel Vault - Tauri Icon Generator")
    print("=" * 55)

    if len(sys.argv) < 2:
        print("\n[!] Thieu duong dan anh goc!")
        print(f"\nCach dung: python {sys.argv[0]} <duong_dan_anh_goc>")
        sys.exit(1)

    source_path = sys.argv[1]

    if not os.path.isfile(source_path):
        print(f"\n[!] Khong tim thay file: {source_path}")
        sys.exit(1)

    try:
        original = Image.open(source_path)
        print(f"\nAnh goc: {source_path}")
        print(f"Kich thuoc: {original.size[0]}x{original.size[1]}")
        print(f"Format: {original.format or 'unknown'}")
    except Exception as e:
        print(f"\n[!] Khong the mo anh: {e}")
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\nThu muc output: {OUTPUT_DIR}")
    print(f"\nDang tao icon...")

    for filename, size in REQUIRED_SIZES.items():
        img = resize_with_padding(original, size)
        output_path = OUTPUT_DIR / filename
        img.save(str(output_path), "PNG")
        file_size = os.path.getsize(str(output_path))
        print(f"  + {filename} ({size}x{size}, {file_size:,} bytes)")

    # Tao ICO
    ico_images = {}
    for s in [16, 32, 48, 64, 128, 256]:
        ico_images[s] = resize_with_padding(original, s)
    create_ico(ico_images, str(OUTPUT_DIR / "icon.ico"))

    # Tao ICNS
    icns_images = {}
    for s in [32, 128, 256, 512]:
        icns_images[s] = resize_with_padding(original, s)
    create_icns(icns_images, str(OUTPUT_DIR / "icon.icns"))

    # Tom tat
    print(f"\n{'=' * 55}")
    print(f"  Hoan thanh! Tat ca icon da duoc tao:")
    print(f"{'=' * 55}")
    for f in sorted(os.listdir(str(OUTPUT_DIR))):
        if f.endswith(('.png', '.ico', '.icns')):
            fp = OUTPUT_DIR / f
            print(f"  {f:25s} {os.path.getsize(str(fp)):>8,} bytes")
    print(f"\nGio chay 'tauri dev' thu di cha!")


if __name__ == "__main__":
    main()
