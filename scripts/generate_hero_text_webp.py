from PIL import Image, ImageDraw, ImageFont, ImageFilter
import os

width = 3560
height = 1826
img = Image.new("RGBA", (width, height), (0, 0, 0, 0))

font_path = "d:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/fonts/long.woff"
font_size = 145
font = ImageFont.truetype(font_path, font_size)

words = ["FLAG", "THEFT", "AUTO"]
center_x = 1805
start_y = 220
line_height = 140

# Create a temporary layer for shadows and glow
shadow_layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
draw_shadow = ImageDraw.Draw(shadow_layer)

text_layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
draw_text = ImageDraw.Draw(text_layer)

for i, word in enumerate(words):
    y = start_y + (i * line_height)
    # Measure text
    bbox = font.getbbox(word)
    w = bbox[2] - bbox[0]
    x = center_x - (w // 2)

    # Draw dark shadow
    draw_shadow.text((x + 6, y + 6), word, font=font, fill=(0, 0, 0, 220))
    # Draw neon pink glow
    draw_shadow.text((x, y), word, font=font, fill=(255, 110, 176, 120))

    # Draw crisp white main text
    draw_text.text((x, y), word, font=font, fill=(255, 255, 255, 255))

# Blur shadow layer for glow
shadow_blurred = shadow_layer.filter(ImageFilter.GaussianBlur(radius=8))

# Composite layers
img = Image.alpha_composite(img, shadow_blurred)
img = Image.alpha_composite(img, text_layer)

# Also add subtle subtitle "LOS SANTOS IS YOUR CIPHER"
round_font_path = "d:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/fonts/round-bold.woff"
sub_font = ImageFont.truetype(round_font_path, 32)
sub_text = "LOS SANTOS IS YOUR CIPHER"
sub_bbox = sub_font.getbbox(sub_text)
sub_w = sub_bbox[2] - sub_bbox[0]
sub_x = center_x - (sub_w // 2)
sub_y = start_y + (3 * line_height) + 10

draw = ImageDraw.Draw(img)
draw.text((sub_x + 2, sub_y + 2), sub_text, font=sub_font, fill=(0, 0, 0, 200))
draw.text((sub_x, sub_y), sub_text, font=sub_font, fill=(0, 229, 255, 255))

out_path = "d:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/images/hero-text.webp"
img.save(out_path, "WEBP", quality=95)
print(f"hero-text.webp generated at {out_path}!")
