oh hi uhh

ive only tested this on zig 0.12.0-dev.3652 on windows

only has proper pages for 1x, 2x, and 3x gemini codes

run: `zig build run`

run with args: `zig build run -- --listen 1.2.3.4 --port 1234 --conn_lim 1024` (listens on 1.2.3.4:1234 with 1024 max http connections)

view compile-time options with `zig build --help` (down at the "Project-Specific Options" section)

i would recommend *against* using ReleaseSmall or ReleaseFast optimization modes just in case my code has unchecked buffer overflows
