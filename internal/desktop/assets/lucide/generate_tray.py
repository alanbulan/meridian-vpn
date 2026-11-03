#!/usr/bin/env python3
"""Rasterize the unchanged official network.svg using installed librsvg/Cairo.

Run from any directory: python3 internal/desktop/assets/lucide/generate_tray.py
This is a build-time asset tool, not an application dependency.
"""
import ctypes as C
import ctypes.util
from pathlib import Path


class Rectangle(C.Structure):
    _fields_ = [("x", C.c_double), ("y", C.c_double), ("width", C.c_double), ("height", C.c_double)]


class GError(C.Structure):
    _fields_ = [("domain", C.c_uint32), ("code", C.c_int), ("message", C.c_char_p)]


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, list(arguments)
    return function


def main():
    root = Path(__file__).resolve().parent
    rsvg = C.CDLL(ctypes.util.find_library("rsvg-2"))
    cairo = C.CDLL(ctypes.util.find_library("cairo"))
    gobject = C.CDLL(ctypes.util.find_library("gobject-2.0"))
    glib = C.CDLL(ctypes.util.find_library("glib-2.0"))
    error_type = C.POINTER(GError)
    error = error_type()

    new_svg = bind(rsvg, "rsvg_handle_new_from_file", C.c_void_p, C.c_char_p, C.POINTER(error_type))
    stylesheet = bind(rsvg, "rsvg_handle_set_stylesheet", C.c_int, C.c_void_p, C.c_char_p, C.c_size_t, C.POINTER(error_type))
    render = bind(rsvg, "rsvg_handle_render_document", C.c_int, C.c_void_p, C.c_void_p, C.POINTER(Rectangle), C.POINTER(error_type))
    new_surface = bind(cairo, "cairo_image_surface_create", C.c_void_p, C.c_int, C.c_int, C.c_int)
    new_context = bind(cairo, "cairo_create", C.c_void_p, C.c_void_p)
    write_png = bind(cairo, "cairo_surface_write_to_png", C.c_int, C.c_void_p, C.c_char_p)
    free_context = bind(cairo, "cairo_destroy", None, C.c_void_p)
    free_surface = bind(cairo, "cairo_surface_destroy", None, C.c_void_p)
    unref = bind(gobject, "g_object_unref", None, C.c_void_p)
    free_error = bind(glib, "g_error_free", None, error_type)

    def require(success, operation):
        if not success:
            message = error.contents.message.decode() if error else "renderer returned failure"
            raise RuntimeError(f"{operation}: {message}")

    svg = new_svg(str(root / "network.svg").encode(), C.byref(error))
    surface = context = None
    try:
        require(svg, "load official network.svg")
        css = b"svg { color: #a995ff; }"
        require(stylesheet(svg, css, len(css), C.byref(error)), "set presentation color")
        surface = new_surface(0, 32, 32)  # CAIRO_FORMAT_ARGB32, initially transparent.
        context = new_context(surface)
        viewport = Rectangle(0, 0, 32, 32)
        require(render(svg, context, C.byref(viewport), C.byref(error)), "rasterize SVG")
        status = write_png(surface, str(root / "tray-network.png").encode())
        if status:
            raise RuntimeError(f"write PNG: Cairo status {status}")
    finally:
        if context:
            free_context(context)
        if surface:
            free_surface(surface)
        if svg:
            unref(svg)
        if error:
            free_error(error)


if __name__ == "__main__":
    main()
