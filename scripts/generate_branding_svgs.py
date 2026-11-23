from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from PIL import Image, ImageDraw, ImageFont
import os

font_path = 'd:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/fonts/long.woff'
font = TTFont(font_path)
glyph_set = font.getGlyphSet()
cmap = font.getBestCmap()

def get_word_svg(word, target_baseline_y, target_height, center_x):
    scale = target_height / 700.0
    total_w = sum(glyph_set[cmap[ord(c)]].width for c in word) * scale
    start_x = center_x - (total_w / 2.0)
    
    paths = []
    curr_x = start_x
    for c in word:
        glyph_name = cmap[ord(c)]
        glyph = glyph_set[glyph_name]
        pen = SVGPathPen(glyph_set)
        glyph.draw(pen)
        d = pen.getCommands()
        if d:
            paths.append(f'<path class="st0" d="{d}" transform="translate({curr_x:.2f}, {target_baseline_y:.2f}) scale({scale:.5f}, {-scale:.5f})" />')
        curr_x += glyph.width * scale
    return '\n    '.join(paths)

svg_parts = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<svg id="Layer_1" xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 224 150">',
    '  <defs>',
    '    <style>',
    '      .st0 { fill: #fff; }',
    '    </style>',
    '  </defs>',
    '  <g id="FTA_Stack">',
    '    ' + get_word_svg('FLAG', 50, 36, 112),
    '    ' + get_word_svg('THEFT', 85, 32, 112),
    '    ' + get_word_svg('AUTO', 120, 32, 112),
    '  </g>',
    '</svg>'
]

full_svg = '\n'.join(svg_parts)
with open('d:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/images/big-hero-text.svg', 'w') as f:
    f.write(full_svg)

with open('d:/ctf/FLAG_THEFT_AUTO_FINAL/frontend/public/images/hero-text.svg', 'w') as f:
    f.write(full_svg)

print('big-hero-text.svg & hero-text.svg generated successfully!')
