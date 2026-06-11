"""
Kestrel Vault - Tauri Icon Generator
=====================================
Chạy script này trên Windows để tạo tất cả icon cần thiết cho Tauri.

Cách dùng:
  python generate_tauri_icons.py <đường_dẫn_ảnh_gốc>

Ví dụ:
  python generate_tauri_icons.py E:\Projectnew\kestrel-vault-logo.png
  python generate_tauri_icons.py C:\Users\Huy\Desktop\logo.png

Output sẽ được lưu vào:
  E:\Projectnew\kestrel-vault-source\src-tauri\icons\

Yêu cầu: pip install Pillow
"""

import sys
import os
import struct
from pathlib import Path
from PIL import Image

# === CẤU HÌNH ===
OUTPUT_DIR = r"E:\Projectnew\kestrel-vault-source\src-tauri\icons"

# Các size cần tạo cho Tauri v2
REQUIRED_SIZES = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}


def resize_with_padding(img, size):
    """Resize ảnh giữ nguyên tỉ lệ, thêm padding transparent nếu cần."""
    img = img.convert("RGBA")
    
    # Tính size mới giữ tỉ lệ
    w, h = img.size
    ratio = min(size / w, size / h)
    new_w = int(w * ratio)
    new_h = int(h * ratio)
    
    # Resize với chất lượng cao
    resized = img.resize((new_w, new_h), Image.LANCZOS)
    
    # Tạo canvas mới với padding
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    
    # Center ảnh lên canvas
    offset_x = (size - new_w) // 2
    offset_y = (size - new_h) // 2
    canvas.paste(resized, (offset_x, offset_y), resized)
    
    return canvas


def create_ico(images_dict, output_path):
    """
    Tạo file ICO từ dict {size: PIL_Image} 
    Dùng PNG-based entries (Tauri/GTK hỗ trợ tốt hơn).
    """
    # Sắp xếp theo size tăng dần
    sorted_sizes = sorted(images_dict.keys())
    
    # Thu thập PNG data cho mỗi size
    entries = []
    for size in sorted_sizes:
        img = images_dict[size].convert("RGBA")
        png_bytes = img.tobytes_format("PNG") if hasattr(img, 'tobytes_format') else None
        
        if png_bytes is None:
            # Fallback: lưu vào buffer
            import io
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_bytes = buf.getvalue()
        
        entries.append({
            "width": size if size < 256 else 0,  # ICO spec: 0 = 256
            "height": size if size < 256 else 0,
            "png_data": png_bytes,
        })
    
    # Xây dựng ICO binary
    num_images = len(entries)
    
    # ICO header: 6 bytes
    ico_header = struct.pack("<HHH", 0, 1, num_images)
    
    # Tính offset cho data
    header_size = 6 + (num_images * 16)  # 6 header + 16 per entry
    
    data_blobs = []
    current_offset = header_size
    
    dir_entries = []
    for entry in entries:
        png_len = len(entry["png_data"])
        dir_entry = struct.pack(
            "<BBBBHHII",
            entry["width"],   # width (0 = 256)
            entry["height"],  # height (0 = 256)
            0,                # color palette
            0,                # reserved
            1,                # color planes
            32,               # bits per pixel
            png_len,          # size of image data
            current_offset,   # offset of image data
        )
        dir_entries.append(dir_entry)
        data_blobs.append(entry["png_data"])
        current_offset += png_len
    
    # Ghi file
    with open(output_path, "wb") as f:
        f.write(ico_header)
        for de in dir_entries:
            f.write(de)
        for blob in data_blobs:
            f.write(blob)
    
    print(f"  ✓ icon.ico ({num_images} sizes, {os.path.getsize(output_path):,} bytes)")


def create_icns(images_dict, output_path):
    """
    Tạo file ICNS (macOS icon) đơn giản.
    Dùng PNG-based icon type (icp4, icp5, ic07).
    """
    # Mapping size -> ICNS type code
    size_to_code = {
        16: b"icp4",    # 16x16
        32: b"icp4",    # 32x32 (also icp4 for HiDPI)
        64: b"icp5",    # 64x64
        128: b"icp5",   # 128x128 (also icp5 for HiDPI)  
        256: b"ic07",   # 256x256
        512: b"ic09",   # 512x512
    }
    
    import io
    
    chunks = []
    for size, img in sorted(images_dict.items()):
        code = size_to_code.get(size, b"icp5")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_data = buf.getvalue()
        
        # ICNS chunk: 4-byte type + 4-byte length (including header) + data
        chunk_length = 8 + len(png_data)
        chunk = code + struct.pack(">I", chunk_length) + png_data
        chunks.append(chunk)
    
    # Full ICNS: "icns" magic + total length + all chunks
    total_length = 8 + sum(len(c) for c in chunks)
    icns_data = b"icns" + struct.pack(">I", total_length)
    for chunk in chunks:
        icns_data += chunk
    
    with open(output_path, "wb") as f:
        f.write(icns_data)
    
    print(f"  ✓ icon.icns ({len(chunks)} sizes, {os.path.getsize(output_path):,} bytes)")


def main():
    print("=" * 55)
    print("  Kestrel Vault - Tauri Icon Generator")
    print("=" * 55)
    
    # === Kiểm tra input ===
    if len(sys.argv) < 2:
        print("\n❌ Thiếu đường dẫn ảnh gốc!")
        print(f"\nCách dùng: python {sys.argv[0]} <đường_dẫn_ảnh_gốc>")
        print(f"\nVí dụ:")
        print(f"  python {sys.argv[0]} E:\\Projectnew\\kestrel-vault-logo.png")
        print(f"  python {sys.argv[0]} C:\\Users\\Huy\\Desktop\\logo.png")
        sys.exit(1)
    
    source_path = sys.argv[1]
    
    if not os.path.isfile(source_path):
        print(f"\n❌ Không tìm thấy file: {source_path}")
        sys.exit(1)
    
    # === Mở ảnh gốc ===
    try:
        original = Image.open(source_path)
        print(f"\n📷 Ảnh gốc: {source_path}")
        print(f"   Kích thước: {original.size[0]}x{original.size[1]}")
        print(f"   Format: {original.format or 'unknown'}")
    except Exception as e:
        print(f"\n❌ Không thể mở ảnh: {e}")
        sys.exit(1)
    
    # === Tạo thư mục output ===
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n📁 Thư mục output: {OUTPUT_DIR}")
    
    # === Tạo từng size PNG ===
    print(f"\n🔧 Đang tạo icon...")
    
    all_images = {}  # {size: PIL_Image} - dùng cho ICO/ICNS
    
    for filename, size in REQUIRED_SIZES.items():
        img = resize_with_padding(original, size)
        output_path = os.path.join(OUTPUT_DIR, filename)
        img.save(output_path, "PNG")
        file_size = os.path.getsize(output_path)
        print(f"  ✓ {filename} ({size}x{size}, {file_size:,} bytes)")
        all_images[size] = img
    
    # === Tạo ICO ===
    ico_images = {
        16: resize_with_padding(original, 16),
        32: resize_with_padding(original, 32),
        48: resize_with_padding(original, 48),
        64: resize_with_padding(original, 64),
        128: resize_with_padding(original, 128),
        256: resize_with_padding(original, 256),
    }
    ico_path = os.path.join(OUTPUT_DIR, "icon.ico")
    create_ico(ico_images, ico_path)
    
    # === Tạo ICNS ===
    icns_images = {
        32: resize_with_padding(original, 32),
        128: resize_with_padding(original, 128),
        256: resize_with_padding(original, 256),
        512: resize_with_padding(original, 512),
    }
    icns_path = os.path.join(OUTPUT_DIR, "icon.icns")
    create_icns(icns_images, icns_path)
    
    # === Tóm tắt ===
    print(f"\n{'=' * 55}")
    print(f"  ✅ Hoàn thành! Tất cả icon đã được tạo:")
    print(f"{'=' * 55}")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.endswith(('.png', '.ico', '.icns')):
            fp = os.path.join(OUTPUT_DIR, f)
            print(f"  📄 {f:25s} {os.path.getsize(fp):>8,} bytes")
    print(f"\n🚀 Giờ chạy 'tauri dev' thử đi cha!")


if __name__ == "__main__":
    main()
