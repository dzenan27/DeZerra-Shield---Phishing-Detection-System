"""
Run this script to generate placeholder PNG icons.
Replace with proper SVG icons before publishing.
pip install Pillow --break-system-packages
"""
from PIL import Image, ImageDraw
import os

sizes = [16, 48, 128]
for size in sizes:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Dark shield background
    draw.ellipse([0, 0, size-1, size-1], fill=(29, 78, 216, 255))
    img.save(f"icon{size}.png")
    print(f"Created icon{size}.png")
