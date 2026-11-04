#!/usr/bin/env python3
"""Read-only Pango glyph-coverage check for disposable installer acceptance.

Uses the same system font fallback stack as the GUI. This checks representative
labels, not complete visual layout or interactive desktop/VPN behavior.
"""
import ctypes
import sys

LABELS = 'Meridian VPN 连接 设置 密码 退出 身份验证 导入 删除 网络 授权 取消 确认 配置 不可用 重新认证'
FONTS = ('Sans 12', 'Sans Bold 12')


def unknown_glyphs(text, font):
    pango = ctypes.CDLL('libpango-1.0.so.0')
    cairo = ctypes.CDLL('libpangocairo-1.0.so.0')
    objects = ctypes.CDLL('libgobject-2.0.so.0')
    pointer = ctypes.c_void_p
    def bind(library, name, args, result):
        function = getattr(library, name)
        function.argtypes, function.restype = args, result
        return function
    font_map = bind(cairo, 'pango_cairo_font_map_get_default', [], pointer)()
    if not font_map:
        raise RuntimeError('Pango default font map unavailable')
    context = bind(pango, 'pango_font_map_create_context', [pointer], pointer)(font_map)
    if not context:
        raise RuntimeError('Pango context unavailable')
    unref = bind(objects, 'g_object_unref', [pointer], None)
    layout = description = None
    free_description = bind(pango, 'pango_font_description_free', [pointer], None)
    try:
        layout = bind(pango, 'pango_layout_new', [pointer], pointer)(context)
        description = bind(pango, 'pango_font_description_from_string', [ctypes.c_char_p], pointer)(font.encode('utf-8'))
        if not layout or not description:
            raise RuntimeError('Pango layout/font description unavailable')
        bind(pango, 'pango_layout_set_font_description', [pointer, pointer], None)(layout, description)
        encoded = text.encode('utf-8')
        bind(pango, 'pango_layout_set_text', [pointer, ctypes.c_char_p, ctypes.c_int], None)(layout, encoded, len(encoded))
        return bind(pango, 'pango_layout_get_unknown_glyphs_count', [pointer], ctypes.c_int)(layout)
    finally:
        if description:
            free_description(description)
        if layout:
            unref(layout)
        unref(context)
    # font_map is borrowed from Pango and must not be unreferenced.


def main():
    try:
        for font in FONTS:
            missing = unknown_glyphs(LABELS, font)
            if missing != 0:
                raise RuntimeError(f'{font}: {missing} unknown UI glyphs')
    except (OSError, AttributeError, RuntimeError) as error:
        print(f'FAIL: Chinese UI font coverage unavailable: {error}', file=sys.stderr)
        return 1
    print('PASS: representative Chinese UI labels have zero unknown Pango glyphs (regular and bold).')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
