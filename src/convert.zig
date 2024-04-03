const std = @import("std");
const opt = @import("options");
const template_dir = opt.template_dir;

const unescape = @import("url_unescape.zig").unescape;

pub const HtmlSanitizer = @import("htmlsanitizer.zig");

// TODO: get rid of line buffer
var linebuf: [opt.max_line_len]u8 = undefined;
pub fn convertGemtext(rd: anytype, wr: anytype, base: std.Uri) !void {
    try wr.writeAll(@embedFile(template_dir ++ "/start.html"));
    while (true) {
        var line = rd.readUntilDelimiter(&linebuf, '\n') catch |e| switch (e) {
            error.EndOfStream => break,
            // error.StreamTooLong => @panic("asdfasdf"),
            else => return e,
        };
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (std.mem.startsWith(u8, line, "=>")) {
            var idx: usize = 2;
            while (idx < line.len and isWhitespace(line[idx])) idx += 1;
            const url_start = idx;
            while (idx < line.len and !isWhitespace(line[idx])) idx += 1;
            const link_url_raw = line[url_start..idx];
            while (idx < line.len and isWhitespace(line[idx])) idx += 1;
            var comment = line[idx..];

            if (comment.len == 0) comment = link_url_raw;

            var urlbuf2: [opt.max_path_len * 2]u8 = undefined;
            if (toProxyPath(base, link_url_raw, &urlbuf2) catch null) |h| {
                try wr.print("<a href=\"{}\">{}</a><br>", .{ HtmlSanitizer{ .data = h }, HtmlSanitizer{ .data = comment } });
            } else {
                try wr.print("<a href=\"{}\">{}</a><br>", .{ HtmlSanitizer{ .data = link_url_raw }, HtmlSanitizer{ .data = comment } });
            }
        } else if (std.mem.startsWith(u8, line, "```")) {
            line = undefined;
            try wr.writeAll("<div><pre>\n");
            while (true) {
                var line2 = rd.readUntilDelimiter(&linebuf, '\n') catch |e| switch (e) {
                    error.EndOfStream => break,
                    else => return e,
                };
                if (line2.len > 0 and line2[line2.len - 1] == '\r') line2 = line2[0 .. line2.len - 1];
                if (std.mem.startsWith(u8, line2, "```")) break;
                try wr.print("{}\n", .{HtmlSanitizer{ .data = line2 }});
            }
            // std.Uri.res
            try wr.writeAll("</pre></div>");
        } else if (line.len > 0 and line[0] == '#') {
            const level: u8 = if (line.len <= 1 or line[1] != '#') 1 else if (line.len <= 2 or line[2] != '#') 2 else 3;
            line = line[level..];
            try wr.print("<h{d}>{}</h{d}>", .{ level, HtmlSanitizer{ .data = line }, level });
        } else if (line.len == 0) {
            try wr.writeAll("<p></p>");
        } else {
            try wr.print("<p>{}</p>", .{HtmlSanitizer{ .data = line }});
        }
    }
    try wr.writeAll("</body>");
}

fn isWhitespace(ch: u8) bool {
    return ch == ' ' or ch == '\t';
}

pub fn parseProxyPath(path: []const u8, buf: []u8) !std.Uri {
    buf[0] = '/';
    var url = try std.Uri.parseWithoutScheme(buf[0 .. (try unescape(path, buf[1..])).len + 1]);
    url.scheme = "gemini";
    return url;
}

pub fn toProxyPath(base: std.Uri, uri: []const u8, buf: []u8) !?[]u8 {
    const buf1 = buf[0 .. buf.len / 2];
    const buf2 = buf[buf.len / 2 ..];
    const uri2 = try unescape(uri, buf1);
    const nurl = std.Uri.resolve_inplace(base, uri2, buf1) catch |e| switch (e) {
        error.OutOfMemory => return error.UriTooLong,
        else => return e,
    };
    if (!std.mem.eql(u8, nurl.scheme, "gemini")) return null;
    return std.fmt.bufPrint(buf2, "/{@+/?#r}", .{nurl}) catch return error.UriTooLong;
}
