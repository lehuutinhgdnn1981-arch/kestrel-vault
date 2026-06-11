from PIL import Image
import os, struct

OUTPUT_DIR = "/home/z/my-project/kestrel-vault-icons"

# Load the 512x512 icon.png as source
source = Image.open(os.path.join(OUTPUT_DIR, "icon.png"))

# Generate proper ICO with embedded PNGs (modern ICO format)
ico_sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
images = []
for sz in ico_sizes:
    resized = source.resize(sz, Image.LANCZOS)
    images.append(resized)

ico_path = os.path.join(OUTPUT_DIR, "icon.ico")
images[0].save(
    ico_path,
    format='ICO',
    sizes=[(img.width, img.height) for img in images],
    append_images=images[1:]
)
fsize = os.path.getsize(ico_path)
print(f"Fixed icon.ico: {fsize:,} bytes")

# For ICNS, create a proper icns file
# ICNS format: header (4 bytes type + 4 bytes size) + data
# We'll use the 'icp4' (16x16), 'icp5' (32x32), 'icp6' (64x64), 'ic07' (128x128), 'ic08' (256x256), 'ic09' (512x512) types
# Modern macOS supports PNG data inside ICNS

def create_icns(images_dict, output_path):
    """Create a valid ICNS file with PNG data"""
    # ICNS type to size mapping
    icns_types = {
        16: b'icp4',    # 16x16
        32: b'icp5',    # 32x32
        64: b'icp6',    # 64x64 (actually this is icp6 for 32x32@2x)
        128: b'ic07',   # 128x128
        256: b'ic08',   # 256x256
        512: b'ic09',   # 512x512
    }
    
    data = b''
    for size, img in sorted(images_dict.items()):
        if size in icns_types:
            png_data = img.tobytes()  # We need PNG bytes
            # Save to buffer
            import io
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            png_bytes = buf.getvalue()
            
            icon_type = icns_types[size]
            icon_size = len(png_bytes) + 8  # 8 bytes for type + size header
            data += icon_type + struct.pack('>I', icon_size) + png_bytes
    
    # Write ICNS file
    with open(output_path, 'wb') as f:
        f.write(b'icns' + struct.pack('>I', len(data) + 8) + data)

# Prepare images for ICNS
source_sizes = {16: 16, 32: 32, 64: 64, 128: 128, 256: 256, 512: 512}
icns_images = {}
for sz, px in source_sizes.items():
    resized = source.resize((px, px), Image.LANCZOS)
    icns_images[sz] = resized

icns_path = os.path.join(OUTPUT_DIR, "icon.icns")
create_icns(icns_images, icns_path)
fsize = os.path.getsize(icns_path)
print(f"Fixed icon.icns: {fsize:,} bytes")

print("\n--- Final file sizes ---")
for f in sorted(os.listdir(OUTPUT_DIR)):
    if f.endswith('.py'):
        continue
    fp = os.path.join(OUTPUT_DIR, f)
    print(f"  {f}: {os.path.getsize(fp):,} bytes")

