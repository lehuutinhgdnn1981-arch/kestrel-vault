#!/usr/bin/env python3
"""
Kestrel Vault Icon Generator
=============================
Chạy script này trên Windows để generate tất cả icon files cho Tauri app.

Cách dùng:
  1. Cài Pillow:  pip install Pillow
  2. Chạy script: python generate_kestrel_icons.py

Icon files sẽ được tạo tại:
  E:\Projectnew\kestrel-vault-source\src-tauri\icons\
"""

import os
import sys
import struct
import io

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("❌ Cần cài Pillow trước! Chạy lệnh: pip install Pillow")
    sys.exit(1)

# ============================================================
# CẤU HÌNH - Thay đổi đường dẫn nếu cần
# ============================================================
OUTPUT_DIR = r"E:\Projectnew\kestrel-vault-source\src-tauri\icons"

# Màu sắc - Tùy chỉnh nếu muốn
COLOR_SHIELD_OUTER   = (20, 22, 40, 255)    # Viền ngoài (dark)
COLOR_SHIELD_INNER   = (35, 38, 85, 255)    # Thân khiên (indigo)
COLOR_HIGHLIGHT      = (55, 60, 130, 255)   # Dải sáng phía trên
COLOR_ACCENT         = (80, 200, 255, 180)  # Đường kẻ ngang (cyan)
COLOR_TEXT_SHADOW    = (0, 0, 0, 120)       # Bóng chữ
COLOR_TEXT           = (200, 230, 255, 255) # Chữ KV
COLOR_LOCK           = (80, 200, 255, 200)  # Khóa
COLOR_LOCK_INNER     = (20, 22, 50, 255)    # Lỗ khóa
COLOR_SHADOW         = (0, 0, 0, 50)        # Bóng khiên


def find_font(size):
    """Tìm font bold phù hợp trên Windows"""
    windows_fonts = [
        r"C:\Windows\Fonts\arialbd.ttf",      # Arial Bold
        r"C:\Windows\Fonts\arial.ttf",         # Arial
        r"C:\Windows\Fonts\calibrib.ttf",      # Calibri Bold
        r"C:\Windows\Fonts\calibri.ttf",       # Calibri
        r"C:\Windows\Fonts\segoeuib.ttf",      # Segoe UI Bold
        r"C:\Windows\Fonts\segoeui.ttf",       # Segoe UI
        r"C:\Windows\Fonts\tahomabd.ttf",      # Tahoma Bold
        r"C:\Windows\Fonts\tahoma.ttf",        # Tahoma
        r"C:\Windows\Fonts\verdanab.ttf",      # Verdana Bold
        r"C:\Windows\Fonts\verdana.ttf",       # Verdana
    ]
    
    for font_path in windows_fonts:
        if os.path.exists(font_path):
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                continue
    
    # Fallback to default
    print("  ⚠️  Không tìm thấy font, dùng default")
    return ImageFont.load_default()


def create_shield_icon(size):
    """Tạo icon khiên KV tại kích thước cho trước"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    s = size / 512.0  # Scale factor
    cx = size / 2
    
    # ---- Điểm khiên ----
    shield_points = [
        (cx, 30 * s),
        (cx + 195 * s, 75 * s),
        (cx + 210 * s, 280 * s),
        (cx + 170 * s, 400 * s),
        (cx, 485 * s),
        (cx - 170 * s, 400 * s),
        (cx - 210 * s, 280 * s),
        (cx - 195 * s, 75 * s),
    ]
    
    # Bóng khiên
    shadow_pts = [(x + 10*s, y + 10*s) for x, y in shield_points]
    draw.polygon(shadow_pts, fill=COLOR_SHADOW)
    
    # Viền ngoài (dark)
    draw.polygon(shield_points, fill=COLOR_SHIELD_OUTER)
    
    # Thân khiên (inner)
    margin = 16 * s
    inner_points = [
        (cx, 30*s + margin),
        (cx + 195*s - margin, 75*s + margin),
        (cx + 210*s - margin, 280*s - margin/2),
        (cx + 170*s - margin, 400*s - margin),
        (cx, 485*s - margin),
        (cx - 170*s + margin, 400*s - margin),
        (cx - 210*s + margin, 280*s - margin/2),
        (cx - 195*s + margin, 75*s + margin),
    ]
    draw.polygon(inner_points, fill=COLOR_SHIELD_INNER)
    
    # Dải sáng phía trên
    highlight_points = [
        (cx, 48*s),
        (cx + 168*s, 92*s),
        (cx + 148*s, 150*s),
        (cx, 120*s),
        (cx - 148*s, 150*s),
        (cx - 168*s, 92*s),
    ]
    draw.polygon(highlight_points, fill=COLOR_HIGHLIGHT)
    
    # Đường kẻ ngang accent
    accent_y = 258 * s
    draw.rectangle(
        [cx - 80*s, accent_y - 3*s, cx + 80*s, accent_y + 3*s],
        fill=COLOR_ACCENT
    )
    
    # ---- Chữ KV ----
    font_size = max(int(130 * s), 8)
    font = find_font(font_size)
    
    text = "KV"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    tx = cx - tw / 2
    ty = 155 * s - th / 2 + 10 * s
    
    # Bóng chữ
    draw.text((tx + 3*s, ty + 3*s), text, fill=COLOR_TEXT_SHADOW, font=font)
    # Chữ chính
    draw.text((tx, ty), text, fill=COLOR_TEXT, font=font)
    
    # ---- Khóa icon ----
    lock_cx = cx
    lock_cy = 375 * s
    
    # Thân khóa
    draw.rounded_rectangle(
        [lock_cx - 30*s, lock_cy - 10*s, lock_cx + 30*s, lock_cy + 25*s],
        radius=max(int(6*s), 1),
        fill=COLOR_LOCK
    )
    
    # Càng khóa
    draw.arc(
        [lock_cx - 18*s, lock_cy - 35*s, lock_cx + 18*s, lock_cy - 2*s],
        start=180, end=0,
        fill=COLOR_LOCK,
        width=max(int(6*s), 2)
    )
    
    # Lỗ khóa
    draw.ellipse(
        [lock_cx - 6*s, lock_cy - 2*s, lock_cx + 6*s, lock_cy + 10*s],
        fill=COLOR_LOCK_INNER
    )
    draw.rectangle(
        [lock_cx - 3*s, lock_cy + 6*s, lock_cx + 3*s, lock_cy + 18*s],
        fill=COLOR_LOCK_INNER
    )
    
    return img


def create_ico_file(source_img, output_path):
    """Tạo file ICO với nhiều kích thước (PNG-based, tương thích Vista+)"""
    ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    
    png_entries = []
    for w, h in ico_sizes:
        resized = source_img.resize((w, h), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format='PNG')
        png_data = buf.getvalue()
        png_entries.append((w, h, png_data))
    
    # ICO header: reserved(2) + type(2) + count(2)
    header = struct.pack('<HHH', 0, 1, len(png_entries))
    
    directory = b''
    data_offset = 6 + len(png_entries) * 16
    png_blobs = b''
    
    for w, h, png_data in png_entries:
        bw = w if w < 256 else 0
        bh = h if h < 256 else 0
        entry = struct.pack('<BBBBHHII',
            bw, bh, 0, 0, 1, 32,
            len(png_data),
            data_offset + len(png_blobs)
        )
        directory += entry
        png_blobs += png_data
    
    with open(output_path, 'wb') as f:
        f.write(header + directory + png_blobs)


def create_icns_file(source_img, output_path):
    """Tạo file ICNS (macOS) với PNG data"""
    icns_types = {
        16: b'icp4',
        32: b'icp5',
        64: b'icp6',
        128: b'ic07',
        256: b'ic08',
        512: b'ic09',
        1024: b'ic10',
    }
    
    data = b''
    for px_size, icon_type in sorted(icns_types.items()):
        if px_size > source_img.width:
            continue
        resized = source_img.resize((px_size, px_size), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format='PNG')
        png_bytes = buf.getvalue()
        
        icon_size = len(png_bytes) + 8
        data += icon_type + struct.pack('>I', icon_size) + png_bytes
    
    with open(output_path, 'wb') as f:
        f.write(b'icns' + struct.pack('>I', len(data) + 8) + data)


def main():
    print("=" * 60)
    print("  🛡️  Kestrel Vault - Icon Generator")
    print("=" * 60)
    print()
    
    # Tạo thư mục nếu chưa có
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"📁 Output: {OUTPUT_DIR}")
    print()
    
    # Tạo icon master 512x512
    print("🎨 Đang tạo icon 512x512...")
    master = create_shield_icon(512)
    
    # ---- Tạo các file PNG ----
    png_files = {
        '32x32.png': 32,
        '128x128.png': 128,
        '128x128@2x.png': 256,
        'icon.png': 512,
    }
    
    print("📦 Đang generate PNG files...")
    for filename, size in png_files.items():
        filepath = os.path.join(OUTPUT_DIR, filename)
        if size == 512:
            img = master
        else:
            img = master.resize((size, size), Image.LANCZOS)
        img.save(filepath, 'PNG', optimize=True)
        fsize = os.path.getsize(filepath)
        print(f"  ✅ {filename:20s} ({size:3d}x{size:<3d})  {fsize:>8,} bytes")
    
    # ---- Tạo file ICO ----
    print("📦 Đang generate ICO file...")
    ico_path = os.path.join(OUTPUT_DIR, 'icon.ico')
    create_ico_file(master, ico_path)
    fsize = os.path.getsize(ico_path)
    print(f"  ✅ {'icon.ico':20s} (multi-size)  {fsize:>8,} bytes")
    
    # ---- Tạo file ICNS ----
    print("📦 Đang generate ICNS file...")
    icns_path = os.path.join(OUTPUT_DIR, 'icon.icns')
    create_icns_file(master, icns_path)
    fsize = os.path.getsize(icns_path)
    print(f"  ✅ {'icon.icns':20s} (multi-size)  {fsize:>8,} bytes")
    
    print()
    print("=" * 60)
    print("  ✅ HOÀN THÀNH! Tất cả icon files đã được tạo!")
    print("=" * 60)
    print()
    print("  Files đã tạo:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        fp = os.path.join(OUTPUT_DIR, f)
        if os.path.isfile(fp):
            print(f"    📄 {f}  ({os.path.getsize(fp):,} bytes)")
    print()
    print("  Giờ chạy lại: tauri dev")
    print()


if __name__ == '__main__':
    main()
