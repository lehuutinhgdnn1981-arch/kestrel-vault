from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math
import os
import io

OUTPUT_DIR = "/home/z/my-project/kestrel-vault-icons"

def create_shield_icon_512():
    """Create a professional shield icon at 512x512, then we downscale"""
    size = 512
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    cx, cy = 256, 256
    
    # Shield outline points
    shield_points = [
        (256, 30),     # top center
        (451, 75),     # top right  
        (466, 280),    # mid right
        (426, 400),    # lower right
        (256, 485),    # bottom
        (86, 400),     # lower left
        (46, 280),     # mid left
        (61, 75),      # top left
    ]
    
    # Drop shadow
    shadow_pts = [(x+10, y+10) for x,y in shield_points]
    draw.polygon(shadow_pts, fill=(0, 0, 0, 50))
    
    # Outer shield border (dark)
    draw.polygon(shield_points, fill=(20, 22, 40, 255))
    
    # Inner shield
    margin = 16
    inner_points = [
        (256, 30 + margin),
        (451 - margin, 75 + margin),
        (466 - margin, 280 - margin//2),
        (426 - margin, 400 - margin),
        (256, 485 - margin),
        (86 + margin, 400 - margin),
        (46 + margin, 280 - margin//2),
        (61 + margin, 75 + margin),
    ]
    
    # Main shield body - deep indigo blue
    draw.polygon(inner_points, fill=(35, 38, 85, 255))
    
    # Top highlight band
    highlight_points = [
        (256, 48),
        (420, 92),
        (400, 150),
        (256, 120),
        (112, 150),
        (92, 92),
    ]
    draw.polygon(highlight_points, fill=(55, 60, 130, 255))
    
    # Diagonal accent stripe (left to right) 
    draw.polygon([
        (100, 250), (140, 230), (412, 320), (372, 340)
    ], fill=(80, 200, 255, 60))
    
    # Central horizontal accent line
    draw.rectangle([130, 258, 382, 264], fill=(80, 200, 255, 180))
    
    # KV Text
    try:
        font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 130)
    except:
        font = ImageFont.load_default()
    
    text = "KV"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    tx = cx - tw / 2
    ty = 155
    
    # Text shadow
    draw.text((tx+3, ty+3), text, fill=(0, 0, 0, 120), font=font)
    # Main text
    draw.text((tx, ty), text, fill=(200, 230, 255, 255), font=font)
    
    # Lock icon at bottom
    lock_cx, lock_cy = 256, 375
    # Lock body
    draw.rounded_rectangle(
        [lock_cx-30, lock_cy-10, lock_cx+30, lock_cy+25],
        radius=6, fill=(80, 200, 255, 200)
    )
    # Shackle
    draw.arc(
        [lock_cx-18, lock_cy-35, lock_cx+18, lock_cy-2],
        start=180, end=0, fill=(80, 200, 255, 200), width=6
    )
    # Keyhole
    draw.ellipse([lock_cx-6, lock_cy-2, lock_cx+6, lock_cy+10], fill=(20, 22, 50, 255))
    draw.rectangle([lock_cx-3, lock_cy+6, lock_cx+3, lock_cy+18], fill=(20, 22, 50, 255))
    
    return img

# Generate master 512x512 icon
master = create_shield_icon_512()
master_path = os.path.join(OUTPUT_DIR, "icon.png")
master.save(master_path, 'PNG', optimize=True)
print(f"icon.png (512x512): {os.path.getsize(master_path):,} bytes")

# Generate each required size by downscaling
required_sizes = {
    '32x32.png': 32,
    '128x128.png': 128,
    '128x128@2x.png': 256,
}

for filename, size in required_sizes.items():
    resized = master.resize((size, size), Image.LANCZOS)
    filepath = os.path.join(OUTPUT_DIR, filename)
    resized.save(filepath, 'PNG', optimize=True)
    print(f"{filename} ({size}x{size}): {os.path.getsize(filepath):,} bytes")

# Generate ICO
ico_sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
ico_images = []
for sz in ico_sizes:
    ico_images.append(master.resize(sz, Image.LANCZOS))

ico_path = os.path.join(OUTPUT_DIR, "icon.ico")
ico_images[0].save(
    ico_path,
    format='ICO',
    sizes=[(img.width, img.height) for img in ico_images],
    append_images=ico_images[1:]
)
print(f"icon.ico: {os.path.getsize(ico_path):,} bytes")

# Generate ICNS
import struct

def create_icns_file(source_img, output_path):
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
    for size, icon_type in sorted(icns_types.items()):
        if size > source_img.width:
            continue
        resized = source_img.resize((size, size), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format='PNG')
        png_bytes = buf.getvalue()
        
        icon_size = len(png_bytes) + 8
        data += icon_type + struct.pack('>I', icon_size) + png_bytes
    
    with open(output_path, 'wb') as f:
        f.write(b'icns' + struct.pack('>I', len(data) + 8) + data)

icns_path = os.path.join(OUTPUT_DIR, "icon.icns")
create_icns_file(master, icns_path)
print(f"icon.icns: {os.path.getsize(icns_path):,} bytes")

print("\n=== Final icon files ===")
for f in sorted(os.listdir(OUTPUT_DIR)):
    if f.endswith('.py'):
        continue
    fp = os.path.join(OUTPUT_DIR, f)
    print(f"  {f}: {os.path.getsize(fp):,} bytes")

