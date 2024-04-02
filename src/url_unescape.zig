const std = @import("std");

pub fn unescape(input: []const u8, output: []u8) ![]u8 {
    if (input.len > output.len) return error.UriTooLong;
    var outptr: usize = 0;
    var inptr: usize = 0;
    while (inptr < input.len) {
        if (input[inptr] == '%') {
            inptr += 1;
            if (inptr + 2 <= input.len) {
                const value = std.fmt.parseInt(u8, input[inptr..][0..2], 16) catch {
                    output[outptr + 0] = input[inptr + 0];
                    output[outptr + 1] = input[inptr + 1];
                    inptr += 2;
                    outptr += 2;
                    continue;
                };

                output[outptr] = value;

                inptr += 2;
                outptr += 1;
            } else {
                output[outptr] = input[inptr - 1];
                outptr += 1;
            }
        } else {
            output[outptr] = input[inptr];
            inptr += 1;
            outptr += 1;
        }
    }

    return output[0..outptr];
}
