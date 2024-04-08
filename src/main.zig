const std = @import("std");
const clap = @import("clap");
const unescape = @import("url_unescape.zig").unescape;
const convert = @import("convert.zig");
const opt = @import("options");
const template_dir = opt.template_dir;

const c = @cImport({
    @cInclude("bearssl.h");
});

var open_conns: u32 = 0;
var mutex: std.Thread.Mutex = .{};
var condvar: std.Thread.Condition = .{};

pub fn main() !void {
    var heap = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = heap.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help          display help and exit
        \\--listen <str>      ip to listen on (default: 127.0.0.1)
        \\-p, --port <u16>    port to listen on (default: 6969)
        \\--conn_lim <usize>  maximum number of open http connections (default: 512)
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = alloc,
    }) catch |e| {
        try diag.report(std.io.getStdErr().writer(), e);
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }

    const addr_str = res.args.listen orelse "127.0.0.1";
    const port = res.args.port orelse 6969;
    const open_conn_limit = res.args.conn_lim orelse 512;

    // TODO: remove this workaround once resolveIp works on windows
    const addr_parse_fn = if (@import("builtin").os.tag == .windows) std.net.Address.parseIp else std.net.Address.resolveIp;
    const listen_addr = try addr_parse_fn(addr_str, port);

    var socket = try listen_addr.listen(.{});
    std.log.info("listening at {}", .{socket.listen_address});
    while (true) {
        const conn = socket.accept() catch |e| switch (e) {
            error.ConnectionAborted, error.ConnectionResetByPeer => continue,
            else => return e,
        };

        {
            mutex.lock();
            defer mutex.unlock();
            while (open_conns >= open_conn_limit) condvar.wait(&mutex);
            open_conns += 1;
        }

        if (std.Thread.spawn(.{}, work, .{ alloc, conn })) |thr| {
            thr.detach();
        } else |e| {
            conn.stream.close();
            return e;
        }
    }
}

fn work(alloc: std.mem.Allocator, conn: std.net.Server.Connection) void {
    defer {
        mutex.lock();
        defer mutex.unlock();
        open_conns -= 1;
        condvar.signal();
    }

    serve(alloc, conn) catch |e| {
        std.log.err("err {}", .{e});
    };
}

fn serve(alloc: std.mem.Allocator, conn: std.net.Server.Connection) !void {
    defer conn.stream.close();
    var hbuf: [1 << 16]u8 = undefined;
    var server = std.http.Server.init(conn, &hbuf);
    while (true) {
        var req = server.receiveHead() catch |e| switch (e) {
            error.HttpConnectionClosing => break,
            else => return e,
        };
        try handle_req(alloc, &req);
    }
}

fn handle_req(alloc: std.mem.Allocator, req: *std.http.Server.Request) !void {
    if (std.mem.eql(u8, req.head.target, "/favicon.ico")) {
        try req.respond("", .{
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/vnd.microsoft.icon" },
            },
        });
        return;
    }

    if (std.mem.eql(u8, req.head.target, "/style.css")) {
        try req.respond(@embedFile(template_dir ++ "/style.css"), .{
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "text/css; charset=utf-8" },
            },
        });
        return;
    }

    if (std.mem.eql(u8, req.head.target, "/") or std.mem.eql(u8, req.head.target, "")) {
        try req.respond(@embedFile(template_dir ++ "/indexpage.html"), .{
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
            },
        });
        return;
    }

    var urlbuf: [opt.max_path_len + 1]u8 = undefined;
    const proxy_url = convert.parseProxyPath(req.head.target, &urlbuf) catch |e| {
        switch (e) {
            error.UriTooLong => try req.respond("uri too long", .{ .status = .uri_too_long }),
            else => try req.respond("could not parse uri", .{ .status = .bad_request }),
        }
        return;
    };
    std.log.info("proxying {}", .{proxy_url});

    const host = proxy_url.host orelse {
        try req.respond("no host specified", .{ .status = .bad_request });
        return;
    };

    const client_socket = std.net.tcpConnectToHost(alloc, host, 1965) catch |e| {
        if (errorInSet(std.net.TcpConnectToAddressError, e)) {
            try req.respond("couldnt connect to host", .{ .status = .not_found });
        } else {
            try req.respond("host not found", .{ .status = .not_found });
        }
        return;
    };

    // TODO: reuse ssl clients to shorten connection time

    var client: SslConn = undefined;
    defer {
        const err = c.br_ssl_engine_last_error(&client.sc.eng);
        if (err != 0) std.log.err("last bearssl err: {d}", .{err});
    }
    var sslbuf: [c.BR_SSL_BUFSIZE_MONO]u8 = undefined;

    client.init(&sslbuf, client_socket.reader().any(), client_socket.writer().any(), host) catch {
        try req.respond("error while communicating with host (initializing bearssl)", .{ .status = .internal_server_error });
        return;
    };
    client.writer().print("{}\r\n", .{proxy_url}) catch {
        try req.respond("error while communicating with host (writing request)", .{ .status = .internal_server_error });
        return;
    };
    client.flush() catch {
        try req.respond("error while communicating with host (flushing request)", .{ .status = .internal_server_error });
        return;
    };

    const rd = client.reader();

    var buf: [3 + opt.max_meta_len + 2]u8 = undefined;

    var header = rd.readUntilDelimiter(&buf, '\n') catch |e| {
        switch (e) {
            error.EndOfStream, error.StreamTooLong => try req.respond("host returned invalid header", .{ .status = .bad_gateway }),
            else => try req.respond("error while communicating with host (receiving header)", .{ .status = .internal_server_error }),
        }
        return;
    };
    if (header.len > 0 and header[header.len - 1] == '\r') header = header[0 .. header.len - 1];
    if (header.len < 3) {
        try req.respond("host returned invalid header", .{ .status = .bad_gateway });
        return;
    }
    const status = header[0..2];
    const meta = header[3..];

    var send_buf: [opt.send_buf_len]u8 = undefined;
    switch (status[0]) {
        '1' => {
            var resp = req.respondStreaming(.{ .send_buffer = &send_buf });
            try resp.writer().print(@embedFile(template_dir ++ "/input.html"), .{meta});
            try resp.end();
        },
        '2' => {
            var idx: usize = 0;
            while (idx < meta.len and meta[idx] != ';' and meta[idx] != ' ') idx += 1;
            if (std.ascii.eqlIgnoreCase(meta[0..idx], "text/gemini")) {
                var resp = req.respondStreaming(.{
                    .send_buffer = &send_buf,
                    .respond_options = .{ .extra_headers = &.{
                        .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
                    } },
                });
                convert.convertGemtext(rd, resp.writer(), proxy_url) catch |e| {
                    // might fail in the middle of a <pre> block
                    // also ssl connections closed without a close_notify currently return an error too
                    resp.writer().print("<span class=\"error\">internal server error ({})</span>\n", .{e}) catch {};
                    if (e == error.BearSslReadError) {
                        resp.writer().print("<span class=\"error\">bearssl error code: {d}</span>", .{c.br_ssl_engine_last_error(&client.sc.eng)}) catch {};
                    }
                    resp.end() catch {};
                    return e;
                };
                try resp.end();
            } else {
                const content_type = if (std.ascii.eqlIgnoreCase(meta[0..idx], "text/html")) "text/plain" else meta;
                var resp = req.respondStreaming(.{
                    .send_buffer = &send_buf,
                    .respond_options = .{ .extra_headers = &.{
                        .{ .name = "Content-Type", .value = content_type },
                    } },
                });

                pipe(rd, resp.writer(), &struct {
                    var buf2: [opt.send_buf_len]u8 = undefined;
                }.buf2) catch |e| {
                    resp.end() catch {};
                    return e;
                };
                try resp.end();
            }
        },
        '3' => {
            var ubuf: [opt.max_path_len * 2]u8 = undefined;
            const redir_to = (convert.toProxyPath(proxy_url, meta, &ubuf) catch null) orelse meta;
            const http_status: std.http.Status = switch (status[1]) {
                '0' => .found,
                '1' => .moved_permanently,
                else => .found,
            };
            var resp = req.respondStreaming(.{
                .send_buffer = &send_buf,
                .respond_options = .{
                    .status = http_status,
                    .extra_headers = &.{
                        .{ .name = "Location", .value = redir_to },
                    },
                },
            });
            try resp.writer().print("gemini status code {s}: {}", .{ status, convert.HtmlSanitizer{ .data = meta } });
            try resp.end();
        },
        else => {
            var resp = req.respondStreaming(.{ .send_buffer = &send_buf, .respond_options = .{ .extra_headers = &.{
                .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
            } } });
            try resp.writeAll(header);
            try resp.end();
        },
    }
}

fn pipe(rd: anytype, wr: anytype, buf: []u8) !void {
    while (true) {
        const len = try rd.read(buf);
        if (len == 0) break;
        try wr.writeAll(buf[0..len]);
    }
}

const SslConn = struct {
    sc: c.br_ssl_client_context,
    xc: c.br_x509_minimal_context,
    ic: c.br_sslio_context,
    xc2: TrivValidator,
    rd: std.io.AnyReader,
    wr: std.io.AnyWriter,

    pub const Writer = std.io.Writer(*SslConn, error{BearSslWriteError}, write);
    pub const Reader = std.io.Reader(*SslConn, error{BearSslReadError}, read);

    pub fn init(self: *SslConn, buf: []u8, rd: std.io.AnyReader, wr: std.io.AnyWriter, hostname: []const u8) !void {
        self.rd = rd;
        self.wr = wr;
        self.xc2 = TrivValidator{ .child = &self.xc };
        c.br_ssl_client_init_full(&self.sc, &self.xc, null, 0);
        c.br_ssl_engine_set_buffer(&self.sc.eng, buf.ptr, buf.len, 0);
        c.br_ssl_engine_set_x509(&self.sc.eng, &self.xc2.vtable);
        c.br_sslio_init(&self.ic, &self.sc.eng, b_read, @constCast(&self.rd), b_write, @constCast(&self.wr));
        var pbuf: [256]u8 = undefined;
        if (c.br_ssl_client_reset(&self.sc, std.fmt.bufPrintZ(&pbuf, "{s}", .{hostname}) catch return error.HostnameTooLong, 0) != 1) return error.Error;
    }

    pub fn write(self: *SslConn, bytes: []const u8) !usize {
        const len = c.br_sslio_write(&self.ic, bytes.ptr, bytes.len);
        if (len > -1) return @intCast(len);
        return error.BearSslWriteError;
    }

    pub fn read(self: *SslConn, bytes: []u8) !usize {
        const len = c.br_sslio_read(&self.ic, bytes.ptr, bytes.len);
        if (len > -1) return @intCast(len);
        if (c.br_ssl_engine_last_error(&self.sc.eng) == 0) return 0;
        return error.BearSslReadError;
    }

    pub fn writer(self: *SslConn) Writer {
        return .{ .context = self };
    }

    pub fn reader(self: *SslConn) Reader {
        return .{ .context = self };
    }

    pub fn flush(self: *SslConn) !void {
        if (c.br_sslio_flush(&self.ic) != 0) return error.Error;
    }

    export fn b_read(ctx: ?*anyopaque, buf: ?[*]u8, len: usize) c_int {
        const rlen = @as(*const std.io.AnyReader, @alignCast(@ptrCast(ctx.?))).read(buf.?[0..len]) catch @panic("asdf");
        return if (rlen == 0) -1 else @intCast(rlen);
    }
    export fn b_write(ctx: ?*anyopaque, buf: ?[*]const u8, len: usize) c_int {
        const wlen = @as(*const std.io.AnyWriter, @alignCast(@ptrCast(ctx.?))).write(buf.?[0..len]) catch @panic("asdf");
        return if (wlen == 0) -1 else @intCast(wlen);
    }
};

// TODO: do proper TOFU validation
const TrivValidator = extern struct {
    const class = c.br_x509_class{
        .context_size = @sizeOf(TrivValidator),
        .start_chain = start_chain,
        .start_cert = start_cert,
        .append = append,
        .end_cert = end_cert,
        .end_chain = end_chain,
        .get_pkey = get_pkey,
    };

    vtable: ?*const c.br_x509_class = &class,
    child: *c.br_x509_minimal_context,

    export fn start_chain(ctx: ?*?*const c.br_x509_class, server_name: ?[*:0]const u8) void {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        self.child.vtable.*.start_chain.?(&self.child.vtable, server_name);
    }
    export fn start_cert(ctx: ?*?*const c.br_x509_class, len: u32) void {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        self.child.vtable.*.start_cert.?(&self.child.vtable, len);
    }
    export fn append(ctx: ?*?*const c.br_x509_class, buf: ?[*]const u8, len: usize) void {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        self.child.vtable.*.append.?(&self.child.vtable, buf, len);
    }
    export fn end_cert(ctx: ?*?*const c.br_x509_class) void {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        self.child.vtable.*.end_cert.?(&self.child.vtable);
    }
    export fn end_chain(ctx: ?*?*const c.br_x509_class) c_uint {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        const err = self.child.vtable.*.end_chain.?(&self.child.vtable);
        if (err == c.BR_ERR_X509_NOT_TRUSTED) return 0;
        if (err == c.BR_ERR_X509_BAD_SERVER_NAME) return 0;
        return err;
    }
    export fn get_pkey(ctx: ?*const ?*const c.br_x509_class, usages: ?*c_uint) [*c]const c.br_x509_pkey {
        const self: *const TrivValidator = @fieldParentPtr("vtable", ctx.?);
        return self.child.vtable.*.get_pkey.?(&self.child.vtable, usages);
    }
};

fn errorInSet(comptime Set: type, err: anytype) bool {
    @setEvalBranchQuota(1000000);
    return switch (err) {
        inline else => |e| comptime for (@typeInfo(Set).ErrorSet.?) |v| {
            if (std.mem.eql(u8, v.name, @errorName(e))) break true;
        } else false,
    };
}
