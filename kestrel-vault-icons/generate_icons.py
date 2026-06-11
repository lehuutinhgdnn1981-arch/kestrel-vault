from PIL import Image, ImageDraw, ImageFont
import math
import os

OUTPUT_DIR = "/home/z/my-project/kestrel-vault-icons"

def create_shield_icon(size):
    """Create a professional shield icon with 'KV' monogram for Kestrel Vault"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Scale factor
    s = size / 512.0
    
    # Shield shape - filled
    # Shield points (centered in 512x512)
    cx, cy = 256, 256
    
    # Outer shield - gradient effect with multiple layers
    # Dark outer border
    shield_points_outer = [
        (cx, 40*s),           # top center
        (cx + 195*s, 80*s),   # top right
        (cx + 210*s, 280*s),  # mid right
        (cx + 170*s, 400*s),  # lower right
        (cx, 480*s),          # bottom center
        (cx - 170*s, 400*s),  # lower left
        (cx - 210*s, 280*s),  # mid left
        (cx - 195*s, 80*s),   # top left
    ]
    
    # Draw shadow first
    shadow_offset = int(8 * s)
    shadow_points = [(x + shadow_offset, y + shadow_offset) for x, y in shield_points_outer]
    draw.polygon(shadow_points, fill=(0, 0, 0, 60))
    
    # Draw outer shield (dark border)
    draw.polygon(shield_points_outer, fill=(30, 30, 45, 255))
    
    # Inner shield (main body) - slightly smaller
    inner_margin = int(14 * s)
    shield_points_inner = [
        (cx, 40*s + inner_margin),
        (cx + 195*s - inner_margin, 80*s + inner_margin),
        (cx + 210*s - inner_margin, 280*s - inner_margin//2),
        (cx + 170*s - inner_margin, 400*s - inner_margin),
        (cx, 480*s - inner_margin),
        (cx - 170*s + inner_margin, 400*s - inner_margin),
        (cx - 210*s + inner_margin, 280*s - inner_margin//2),
        (cx - 195*s + inner_margin, 80*s + inner_margin),
    ]
    
    # Main shield color - deep blue/indigo gradient simulation
    # Top part: lighter
    top_color = (55, 60, 120, 255)
    bottom_color = (25, 28, 65, 255)
    
    # Fill with main color
    draw.polygon(shield_points_inner, fill=(40, 45, 95, 255))
    
    # Add a highlight stripe near the top
    highlight_points = [
        (cx, 54*s + inner_margin),
        (cx + 150*s, 94*s + inner_margin),
        (cx + 140*s, 140*s),
        (cx, 120*s),
        (cx - 140*s, 140*s),
        (cx - 150*s, 94*s + inner_margin),
    ]
    draw.polygon(highlight_points, fill=(70, 75, 150, 255))
    
    # Draw center chevron/lock accent
    accent_y = 260 * s
    accent_size = 50 * s
    # Horizontal accent line
    draw.rectangle(
        [cx - 80*s, accent_y - 3*s, cx + 80*s, accent_y + 3*s],
        fill=(100, 200, 255, 200)
    )
    
    # Draw "KV" text
    try:
        font_size = max(int(120 * s), 8)
        # Try to find a good font
        font_paths = [
            '/usr/share/fonts/truetype/english/Tinos-Bold.ttf',
            '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
        ]
        font = None
        for fp in font_paths:
            if os.path.exists(fp):
                font = ImageFont.truetype(fp, font_size)
                break
        if font is None:
            font = ImageFont.load_default()
    except:
        font = ImageFont.load_default()
    
    # Draw KV text
    text = "KV"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    tx = cx - tw / 2
    ty = 155 * s - th / 2 + 10 * s
    
    # Text shadow
    draw.text((tx + 2*s, ty + 2*s), text, fill=(0, 0, 0, 150), font=font)
    # Main text - bright cyan/white
    draw.text((tx, ty), text, fill=(200, 230, 255, 255), font=font)
    
    # Small lock icon at bottom of shield
    lock_cx = cx
    lock_cy = 370 * s
    lock_w = 30 * s
    lock_h = 25 * s
    # Lock body
    draw.rounded_rectangle(
        [lock_cx - lock_w, lock_cy - lock_h/2, lock_cx + lock_w, lock_cy + lock_h],
        radius=int(5*s),
        fill=(100, 200, 255, 220)
    )
    # Lock shackle
    shackle_w = 18 * s
    shackle_h = 20 * s
    draw.arc(
        [lock_cx - shackle_w, lock_cy - lock_h/2 - shackle_h, lock_cx + shackle_w, lock_cy - lock_h/2 + 5*s],
        start=180, end=0,
        fill=(100, 200, 255, 220),
        width=max(int(5*s), 2)
    )
    # Keyhole
    draw.ellipse(
        [lock_cx - 5*s, lock_cy - 5*s, lock_cx + 5*s, lock_cy + 5*s],
        fill=(30, 35, 75, 255)
    )
    draw.rectangle(
        [lock_cx - 2*s, lock_cy + 3*s, lock_cx + 2*s, lock_cy + 12*s],
        fill=(30, 35, 75, 255)
    )
    
    return img

# Generate all required sizes
sizes = {
    '32x32.png': 32,
    '128x128.png': 128,
    '128x128@2x.png': 256,
    'icon.png': 512,
}

for filename, size in sizes.items():
    img = create_shield_icon(size)
    filepath = os.path.join(OUTPUT_DIR, filename)
    # Optimize PNG size - use higher compression
    img.save(filepath, 'PNG', optimize=True)
    fsize = os.path.getsize(filepath)
    print(f"Created {filename}: {size}x{size}, file size: {fsize} bytes")

# Generate ICO file (contains multiple sizes)
ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
ico_images = []
for sz in ico_sizes:
    ico_images.append(create_shield_icon(sz[0]))

ico_path = os.path.join(OUTPUT_DIR, 'icon.ico')
# Save as ICO
ico_images[0].save(
    ico_path,
    format='ICO',
    sizes=ico_sizes,
    append_images=ico_images[1:]
)
fsize = os.path.getsize(ico_path)
print(f"Created icon.ico: file size: {fsize} bytes")

# Generate ICNS (macOS) - we'll create a basic one
# ICNS is complex format, for now create a placeholder PNG that macOS icon utils can use
# Actually, for Tauri on Windows we only need .ico, .icns is for macOS builds
# Let's create a minimal valid icns file
# For simplicity, create a 256x256 PNG and note that Tauri's icon generation handles this
# We'll just create a 512x512 as icon.icns placeholder (Tauri may need actual icns format)
# Actually Tauri needs proper icns - let's skip icns for Windows build and note it

# For Windows, the critical files are: 32x32.png, 128x128.png, 128x128@2x.png, icon.png, icon.ico
# icon.icns is only needed for macOS builds

# Create a simple icns-compatible file (just copy icon.png as placeholder)
# Tauri will use ico for Windows
import shutil
shutil.copy(
    os.path.join(OUTPUT_DIR, 'icon.png'),
    os.path.join(OUTPUT_DIR, 'icon.icns')  # This won't be valid ICNS but Tauri on Windows won't need it
)
print("Created icon.icns (placeholder - only needed for macOS builds)")

print("\n--- All files created ---")
for f in sorted(os.listdir(OUTPUT_DIR)):
    if f == 'generate_icons.py':
        continue
    fp = os.path.join(OUTPUT_DIR, f)
    print(f"  {f}: {os.path.getsize(fp):,} bytes")

