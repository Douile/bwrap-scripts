# Bwrap MPV video player

This script will automatically detect wayland or Xorg and forward the required sockets. Currently
GPU acceleration is not forwarded and does not work. Other video outputs like DRM will also not work.

For sound pulse audio is forwarded (this should also work with pipewire-pulse).

Currently networking is also enabled always (script modification needed to remove), because the
script is geared towards playing networked files (e.g. with yt-dlp) no local files are forwarded
(other than your MPV config if it exists).
