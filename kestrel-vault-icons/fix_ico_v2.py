"""Fix ICO generation - PIL's built-in ICO saving has issues with append_images"""
from PIL import Image
import struct
import io
import os

OUTPUT_DIR = "/home/z/my-project/kestrel-vault-icons"
source = Image.open(os.path.join(OUTPUT_DIR, "icon.png"))

# Create ICO manually using PNG-based entries (valid for Vista+)
ico_sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]

png_entries = []
for w, h in ico_sizes:
    resized = source.resize((w, h), Image.LANCZOS)
    buf = io.BytesIO()
    resized.save(buf, format='PNG')
    png_data = buf.getvalue()
    png_entries.append((w, h, png_data))

# ICO format:
# Header: 6 bytes (reserved:2, type:2, count:2)
# Directory entries: 16 bytes each
# Image data: PNG blobs

header = struct.pack('<HHH', 0, 1, len(png_entries))

directory = b''
data_offset = 6 + len(png_entries) * 16

png_blobs = b''
for w, h, png_data in png_entries:
    # For PNG-based entries, width/height can be 0 (meaning 256+)
    bw = w if w < 256 else 0
    bh = h if h < 256 else 0
    entry = struct.pack('<BBBBHHII',
        bw,     # width (0 = 256)
        bh,     # height (0 = 256)  
        0,      # color palette
        0,      # reserved
        1,      # color planes
        32,     # bits per pixel
        len(png_data),  # size of image data
        data_offset + len(png_blobs)  # offset to image data
    )
    directory += entry
    png_blobs += png_data

ico_data = header + directory + png_blobs

ico_path = os.path.join(OUTPUT_DIR, "icon.ico")
with open(ico_path, 'wb') as f:
    f.write(ico_data)

print(f"icon.ico: {os.path.getsize(ico_path):,} bytes")

# Verify
ico = Image.open(ico_path)
print(f"ICO info sizes: {ico.info.get('sizes', 'unknown')}")

