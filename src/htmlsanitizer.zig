const std = @import("std");

data: []const u8,
pub fn format(
    self: @This(),
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    wr: anytype,
) !void {
    _ = fmt;
    _ = options;
    for (self.data) |ch| {
        try switch (ch) {
            '<' => wr.writeAll("&lt;"),
            '>' => wr.writeAll("&gt;"),
            '&' => wr.writeAll("&amp;"),
            '"' => wr.writeAll("&quot;"),
            else => wr.writeByte(ch),
        };
    }
}
