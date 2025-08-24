const std = @import("std");
const builtin = @import("builtin");
const Tz = @import("tz.zig").Tz;

const fatal = std.process.fatal;
const native_endian = builtin.cpu.arch.endian();

var write_buffer: [4096]u8 = undefined;
var read_buffer: [4096]u8 = undefined;

fn usage(progname: []const u8) noreturn {
    std.log.info(
        \\usage: 
        \\  {0s} --start
        \\  {0s} --log
        \\  {0s} [--log] [--name name | --no-name] [--retain s] cmd [args..]
        \\     everything after options (cmd [args..]) will be given as an argument to sh -c
        \\     and its output will be redirected to the statusbar daemon
        \\     if a line of output is too long, it will be divided into pieces
        \\     max line length might be an option later
        \\ 
        \\    --help -h   this
        \\
        \\    --start     starts the daemon (must be the only arg)
        \\    --log       prints the full log to stdout (must be the only arg)
        \\
        \\  
        \\  args valid when running a child command: (all optional)
        \\    --log        log every line of the redirected program 
        \\                 with timestamps to a temporary file 
        \\                 that is removed when the main daemon exits
        \\                   currently does nothing, everything is logged
        \\    --name name  every line output is prefixed with this name.
        \\                 uses cmd by default
        \\    --no-name    do not prefix output with anything
        \\    --retain s   keep line visible for s seconds or until another
        \\                 line overwrites it
        \\                 if s is 0 (default), line will be visible
        \\                 as long as the program is running and 
        \\                 the line isn't overwritten
        \\ 
    , .{progname});
    std.process.exit(0);
}

const Args = union(enum) {
    log,
    send: Send,
    start,

    const Send = struct {
        log: bool = false,
        name: ?[]const u8 = null,
        retain: u16 = 0,
        cmd: []const []const u8,
    };

    fn parse(raw_args: []const []const u8) !Args {
        const progname = raw_args[0];
        const args = raw_args[1..];
        if (args.len == 0) usage(progname);

        var send: Send = .{ .cmd = undefined };
        var no_name = false;
        var args_idx: usize = 0;
        while (args_idx < args.len) : (args_idx += 1) {
            const arg = args[args_idx];
            if (std.mem.eql(u8, "--help", arg) or std.mem.eql(u8, "-h", arg)) {
                usage(progname);
            } else if (std.mem.eql(u8, "--log", arg)) {
                if (args.len == 1) return Args.log;
                send.log = true;
            } else if (std.mem.eql(u8, "--start", arg)) {
                if (args.len != 1) fatal("--start can only appear alone", .{});
                return Args.start;
            } else if (std.mem.eql(u8, "--name", arg)) {
                args_idx += 1;
                if (args_idx >= args.len) fatal("--name expects an argument", .{});
                send.name = args[args_idx];
            } else if (std.mem.eql(u8, "--no-name", arg)) {
                no_name = true;
            } else if (std.mem.eql(u8, "--retain", arg)) {
                args_idx += 1;
                if (args_idx >= args.len) fatal("--retain expects an argument", .{});
                send.retain = std.fmt.parseUnsigned(@TypeOf(send.retain), args[args_idx], 10) catch |err| switch (err) {
                    error.Overflow => fatal("--retain can at most be {}", .{std.math.maxInt(@TypeOf(send.retain))}),
                    error.InvalidCharacter => fatal("--retain invalid number: {s}", .{args[args_idx]}),
                };
            } else break;
        }
        if (args_idx == args.len) fatal("expected cmd after options", .{});
        send.cmd = args[args_idx..];
        if (!no_name and send.name == null) send.name = args[args_idx];
        return Args{ .send = send };
    }
};

pub fn main() !void {
    const status_socket_name = "statusbar-0";
    const log_file_name = "statusbar-0.log";

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer std.debug.assert(.ok == gpa.deinit());
    const alc = gpa.allocator();

    const args_input = try std.process.argsAlloc(alc);
    defer std.process.argsFree(alc, args_input);

    const run_dir = std.posix.getenv("XDG_RUNTIME_DIR") orelse fatal("XDG_RUNTIME_DIR not in env", .{});
    if (run_dir.len == 0) fatal("XDG_RUNTIME_DIR is an empty string", .{});

    const log_path = try std.mem.join(alc, "/", &.{ run_dir, log_file_name });
    defer alc.free(log_path);
    const socket_path = try std.mem.join(alc, "/", &.{ run_dir, status_socket_name });
    defer alc.free(socket_path);

    const tzfile = try std.fs.openFileAbsolute("/etc/localtime", .{});
    defer tzfile.close();

    var read_buf: [4096]u8 = undefined;
    var tz_reader = tzfile.reader(&read_buf);
    var timezone = try Tz.parse(alc, &tz_reader.interface);
    defer timezone.deinit();

    switch (try Args.parse(args_input)) {
        .log => try printLog(log_path, timezone),
        .send => |args| try sendOutputToDaemon(alc, args, socket_path),
        .start => {
            var log_buf: [1024]u8 = undefined;
            var daemon: Daemon = try .init(alc, socket_path, log_path, &log_buf);
            defer daemon.deinit(socket_path, log_path);
            try daemon.run(timezone);
        },
    }
}

fn writeTime(writer: *std.Io.Writer, seconds: i64, timezone: Tz) !void {
    var i: usize = timezone.transitions.len - 1;
    const tz_seconds = while (i > 0) : (i -= 1) {
        const t = timezone.transitions[i];
        if (seconds > t.ts) break t.timetype.offset + seconds;
    } else unreachable;

    const ep_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(tz_seconds) };
    const ep_day = ep_secs.getEpochDay();
    const year_day = ep_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = ep_secs.getDaySeconds();

    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    // 1970-1-1 was a thursday
    const day_name_idx = (ep_day.day + 3) % 7;
    const day_name = ([_][]const u8{ "Mon", "Tue", "Wen", "Thu", "Fri", "Sat", "Sun" })[day_name_idx];
    const hour = day_secs.getHoursIntoDay();
    const minute = day_secs.getMinutesIntoHour();

    const fmt = "{:0>4}-{:0>2}-{:0>2} {s} {:0>2}:{:0>2}";
    const arg = .{ year, month, day, day_name, hour, minute };
    return writer.print(fmt, arg);
}

fn printLog(log_path: []const u8, timezone: Tz) !void {
    const log_file = std.fs.openFileAbsolute(log_path, .{}) catch |err| switch (err) {
        error.FileNotFound => fatal("could not find log-file: {s}, it is usually available as long as the daemon is running", .{log_path}),
        else => return err,
    };
    defer log_file.close();

    var reader_buf: [4096]u8 = undefined;
    var log_reader = log_file.reader(&reader_buf);
    const log = &log_reader.interface;

    var writer_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&writer_buf);
    const stdout = &stdout_writer.interface;

    while (log.takeInt(i64, .little)) |line_timestamp| {
        try stdout.writeAll("[");
        try writeTime(stdout, line_timestamp, timezone);
        try stdout.writeAll("] ");
        _ = try log.streamDelimiter(stdout, '\n');
        try stdout.writeAll("\n");
    } else |err| switch (err) {
        error.EndOfStream => try stdout.flush(),
        else => return err,
    }
}

fn sendOutputToDaemon(alc: std.mem.Allocator, args: Args.Send, socket_path: []const u8) !void {
    const cmd_line = try std.mem.join(alc, " ", args.cmd);
    defer alc.free(cmd_line);

    const unix_sock = std.net.connectUnixSocket(socket_path) catch |err| switch (err) {
        error.FileNotFound => fatal("cannot connect to daemon, make sure it is started with --start", .{}),
        else => return err,
    };
    defer unix_sock.close();

    var write_buf: [256]u8 = undefined;
    var unix_sock_writer = unix_sock.writer(&write_buf);
    const daemon = &unix_sock_writer.interface;

    var cmd = std.process.Child.init(&.{ "sh", "-c", cmd_line }, alc);
    cmd.stdout_behavior = .Pipe;
    try cmd.spawn();
    var read_buf: [256]u8 = undefined;
    var cmd_out_reader = cmd.stdout.?.reader(&read_buf);
    const cmd_out = &cmd_out_reader.interface;

    if (args.name) |cmd_name| try daemon.print("{s}: ", .{cmd_name});
    while (cmd_out.streamDelimiter(daemon, '\n')) |_| {
        try daemon.writeAll("\n");
        try daemon.flush();
    } else |err| switch (err) {
        error.EndOfStream => {
            try daemon.writeAll("\n");
            try daemon.flush();
        },
        else => return err,
    }
    _ = try cmd.wait();
}

const Daemon = struct {
    alc: std.mem.Allocator,
    signal_fd: std.posix.fd_t,
    server: std.net.Server,
    log_writer: std.fs.File.Writer,
    epoll_fd: i32,
    message: std.ArrayList(u8) = .empty,
    datetime: DateTime,
    audio: Audio,
    battery: ?Battery,

    fn init(alc: std.mem.Allocator, socket_path: []const u8, log_path: []const u8, log_buf: []u8) !Daemon {
        var mask = std.posix.sigemptyset();
        std.posix.sigaddset(&mask, std.os.linux.SIG.INT);
        std.posix.sigaddset(&mask, std.os.linux.SIG.TERM);
        std.posix.sigprocmask(std.os.linux.SIG.BLOCK, &mask, null);

        const signal_fd = try std.posix.signalfd(-1, &mask, 0);
        errdefer std.posix.close(signal_fd);

        const addr = try std.net.Address.initUnix(socket_path);
        var server = addr.listen(.{}) catch |err| switch (err) {
            error.AddressInUse => fatal("daemon already running, or previous socket ({s}) was not removed", .{socket_path}),
            else => return err,
        };
        errdefer server.deinit();
        errdefer std.fs.deleteFileAbsolute(socket_path) catch unreachable;

        var audio = try Audio.init(alc);
        errdefer _ = audio.deinit() catch unreachable;

        const battery = try Battery.init();
        errdefer if (battery) |b| b.deinit();

        var datetime = try DateTime.init();
        errdefer datetime.deinit();

        const epoll_fd = try std.posix.epoll_create1(0);
        errdefer std.posix.close(epoll_fd);

        try addToEpoll(epoll_fd, signal_fd);
        try addToEpoll(epoll_fd, audio.cmd.stdout.?.handle);
        try addToEpoll(epoll_fd, server.stream.handle);
        try addToEpoll(epoll_fd, datetime.timer_fd);
        if (battery) |b| {
            try addToEpoll(epoll_fd, b.ac_netlink.sock.handle);
            try addToEpoll(epoll_fd, b.timer_fd);
        }

        const log_file = try std.fs.createFileAbsolute(log_path, .{});
        errdefer std.fs.deleteFileAbsolute(log_path) catch unreachable;
        errdefer log_file.close();

        return .{
            .alc = alc,
            .signal_fd = signal_fd,
            .server = server,
            .log_writer = log_file.writer(log_buf),
            .epoll_fd = epoll_fd,
            .audio = audio,
            .datetime = datetime,
            .battery = battery,
        };
    }
    fn addToEpoll(epoll_fd: std.posix.fd_t, fd: std.posix.fd_t) !void {
        const EPOLL = std.os.linux.EPOLL;
        var ev: std.os.linux.epoll_event = .{ .data = .{ .fd = fd }, .events = EPOLL.IN };
        try std.posix.epoll_ctl(epoll_fd, EPOLL.CTL_ADD, fd, &ev);
    }

    fn deinit(d: *Daemon, socket_path: []const u8, log_path: []const u8) void {
        std.posix.close(d.signal_fd);
        std.posix.close(d.epoll_fd);
        d.log_writer.file.close();
        d.message.deinit(d.alc);
        d.server.deinit();
        d.datetime.deinit();
        if (d.battery) |bat| bat.deinit();
        std.fs.deleteFileAbsolute(socket_path) catch unreachable;
        std.fs.deleteFileAbsolute(log_path) catch unreachable;
        _ = d.audio.deinit() catch unreachable;
    }

    fn run(d: *Daemon, timezone: Tz) !void {
        const wait_max_events = 16;
        var events: [wait_max_events]std.os.linux.epoll_event = undefined;

        var write_buf: [516]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&write_buf);
        const stdout = &stdout_writer.interface;
        // header for swaybar-protocol
        try stdout.writeAll("{\"version\":1}\n[");

        while (true) {
            try stdout.print("[{{\"full_text\":\"{s} \"}},", .{d.message.items});
            // pango markup to have volume struck out when muted
            try stdout.writeAll("{{\"markup\":\"pango\",\"full_text\": \" ");
            try stdout.print("({s}{s}{d:.2}{s}) ", .{
                if (d.audio.bluetooth) "bt: " else "",
                if (d.audio.muted) "<s>" else "",
                d.audio.volume,
                if (d.audio.muted) "</s>" else "",
            });
            if (d.battery) |bat| {
                try stdout.print("{s}[{}%] ", .{
                    switch (bat.ac_status) {
                        .online => "^",
                        .offline => "",
                        .unknown => "?",
                    },
                    bat.capacity,
                });
            }
            const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
            try writeTime(stdout, ts.sec, timezone);
            try stdout.writeAll("\"}}],");
            try stdout.flush();

            const n_fds = std.posix.epoll_wait(d.epoll_fd, &events, -1);
            var trash_buf: [8]u8 = undefined;
            for (events[0..n_fds]) |ev| {
                const fd = ev.data.fd;
                if (fd == d.signal_fd) {
                    return; // exit cleanly when recieving int or term signals
                } else if (fd == d.server.stream.handle) {
                    const conn = try d.server.accept();
                    try addToEpoll(d.epoll_fd, conn.stream.handle);
                } else if (fd == d.audio.cmd.stdout.?.handle) {
                    try d.audio.updateOnce();
                } else if (fd == d.datetime.timer_fd) {
                    _ = try std.posix.read(d.datetime.timer_fd, &trash_buf); //reset timer
                } else if (d.battery != null and fd == d.battery.?.ac_netlink.sock.handle) {
                    d.battery.?.ac_status = try d.battery.?.ac_netlink.getAcStatus() orelse continue;
                } else if (d.battery != null and fd == d.battery.?.timer_fd) {
                    _ = try std.posix.read(d.battery.?.timer_fd, &trash_buf); //reset timer
                    d.battery.?.capacity = try Battery.getNewCapacity(d.battery.?.cap_files);
                } else {
                    if (d.message.capacity > 1024) try d.message.resize(d.alc, 1024);
                    var msg_writer: std.Io.Writer.Allocating = .fromArrayList(d.alc, &d.message);
                    const msg = &msg_writer.writer;
                    // handle messages from connections accepted earlier (from fd)
                    // reuse write_buf
                    var conn_reader = (std.net.Stream{ .handle = fd }).reader(&write_buf);
                    const conn = conn_reader.interface();
                    // this will not block long, since every message sent by the sender
                    // has to end in a newline, and is sent in full
                    _ = conn.streamDelimiter(msg, '\n') catch |err| switch (err) {
                        error.EndOfStream => {
                            const EPOLL = std.os.linux.EPOLL;
                            try std.posix.epoll_ctl(d.epoll_fd, EPOLL.CTL_DEL, fd, null);
                            std.posix.close(fd);
                        },
                        else => return err,
                    };
                    d.message = msg_writer.toArrayList();

                    const log = &d.log_writer.interface;
                    try log.writeInt(i64, std.time.timestamp(), .little);
                    try log.print("{s}\n", .{d.message.items});
                    try log.flush();
                }
            }
        }
    }
};

const Audio = struct {
    cmd: std.process.Child,
    volume: f16,
    muted: bool,
    bluetooth: bool,

    fn init(alc: std.mem.Allocator) !Audio {
        var tmp_rand: [16]u8 = undefined;
        var tmp_path: [std.fs.base64_encoder.calcSize(16)]u8 = undefined;
        try std.posix.getrandom(&tmp_rand);
        _ = std.fs.base64_encoder.encode(&tmp_path, &tmp_rand);
        @memcpy(tmp_path[0..5], "/tmp/");

        var script_writer = (try std.fs.createFileAbsolute(&tmp_path, .{})).writer(&.{});
        try script_writer.interface.writeAll(@embedFile("audio-info.lua"));
        defer {
            script_writer.file.close();
            std.fs.deleteFileAbsolute(&tmp_path) catch {};
        }
        var cmd = std.process.Child.init(&.{ "wpexec", &tmp_path }, alc);
        cmd.stdout_behavior = .Pipe;
        try cmd.spawn();

        var audio: Audio = .{
            .cmd = cmd,
            .volume = undefined,
            .muted = undefined,
            .bluetooth = undefined,
        };
        try audio.updateOnce();
        return audio;
    }

    fn deinit(a: *Audio) !std.process.Child.Term {
        return a.cmd.kill();
    }

    fn updateOnce(a: *Audio) !void {
        var read_buf: [8]u8 = undefined;
        var cmd_reader = a.cmd.stdout.?.reader(&read_buf);
        const cmd = &cmd_reader.interface;
        a.volume = try std.fmt.parseFloat(f16, try cmd.take(4));
        a.muted = switch (try cmd.takeByte()) {
            't' => true,
            'f' => false,
            else => unreachable,
        };
        a.bluetooth = switch (try cmd.takeByte()) {
            't' => true,
            'f' => false,
            else => unreachable,
        };
        cmd.toss(1); // skip newline;
    }
};

const DateTime = struct {
    timer_fd: i32,

    fn init() !DateTime {
        const timer_fd = try std.posix.timerfd_create(std.os.linux.TIMERFD_CLOCK.REALTIME, .{});
        errdefer std.posix.close(timer_fd);

        var time_spec = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
        //set timespec to last full minute
        time_spec.sec -= @mod(time_spec.sec, 60);
        time_spec.nsec = 0;

        try std.posix.timerfd_settime(timer_fd, .{ .ABSTIME = true }, &.{
            .it_value = time_spec,
            .it_interval = .{ .sec = 60, .nsec = 0 },
        }, null);

        return .{
            .timer_fd = timer_fd,
        };
    }

    fn deinit(dt: *DateTime) void {
        std.posix.close(dt.timer_fd);
    }
};

const Battery = struct {
    cap_files: [2]?std.fs.File,
    capacity: u8,

    ac_netlink: Netlink,
    ac_status: Netlink.AcStatus,
    // timer for reading current battery capacity
    timer_fd: i32,

    fn init() !?Battery {
        const ac = std.fs.openFileAbsolute("/sys/class/power_supply/AC/online", .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer ac.close();

        var ac_reader = ac.reader(&read_buffer);
        const ac_status: Netlink.AcStatus = switch (try ac_reader.interface.takeByte()) {
            '0' => .offline,
            '1' => .online,
            else => .unknown,
        };

        var nl = try Netlink.init();
        errdefer nl.deinit();

        try nl.subscribeToAcpiEvents();

        const b0 = std.fs.openFileAbsolute("/sys/class/power_supply/BAT0/capacity", .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        errdefer if (b0) |f| f.close();

        const b1 = std.fs.openFileAbsolute("/sys/class/power_supply/BAT1/capacity", .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        errdefer if (b1) |f| f.close();

        if (b0 == null and b1 == null) fatal("no battery capacity files found", .{});

        const capacity = try getNewCapacity(.{ b0, b1 });

        const timer_fd = try std.posix.timerfd_create(std.os.linux.TIMERFD_CLOCK.REALTIME, .{});
        errdefer std.posix.close(timer_fd);

        try std.posix.timerfd_settime(timer_fd, .{}, &.{
            .it_value = .{ .sec = 35, .nsec = 0 },
            .it_interval = .{ .sec = 35, .nsec = 0 },
        }, null);

        return .{
            .cap_files = .{ b0, b1 },
            .capacity = capacity,
            .ac_netlink = nl,
            .ac_status = ac_status,
            .timer_fd = timer_fd,
        };
    }

    fn deinit(self: Battery) void {
        self.ac_netlink.deinit();
        std.posix.close(self.timer_fd);
        if (self.cap_files[0]) |f| f.close();
        if (self.cap_files[1]) |f| f.close();
    }

    fn getNewCapacity(files: [2]?std.fs.File) !u8 {
        var cap: u8 = 0;
        var count: u8 = 0;
        for (files) |file| {
            if (file) |f| {
                count += 1;
                var battery_file_reader = f.reader(&read_buffer);
                try battery_file_reader.seekTo(0); // need to read from beginning of file each time
                const battery = &battery_file_reader.interface;

                const int_str = try battery.takeDelimiterExclusive('\n');
                cap += try std.fmt.parseInt(u8, int_str, 10);
            }
        }
        std.debug.assert(count > 0);
        return cap / count;
    }

    const Netlink = struct {
        sock: std.fs.File,
        seq: u32 = 0,

        const linux = std.os.linux;
        const Header = extern struct {
            /// len of entire message including headers
            /// but excluding padding of last attribute?
            len: u32,
            type: u16,
            flags: u16,
            seq: u32,
            pid: u32,
        };
        const Error = extern struct {
            err: i32,
            request: Header,
            //optional request payload, (NLM_F_CAPPED flag or err == 0 means no payload)
            //optional extended ack, (NLM_F_ACK_TLVS flag means extended ack present)
        };
        const Done = extern struct {
            err: i32,
            //optional extended ack
        };
        const Generic = extern struct {
            cmd: u8,
            version: u8 = 1,
            reserved: u16 = 0,
        };
        const CtrlAttr = extern struct {
            len: u16, //not including padding
            type: CTRL_ATTR,
            // payload
            // and padding to reach a multiple of 4 bytes
            const CTRL_ATTR = enum(u16) {
                UNSPEC,
                FAMILY_ID,
                FAMILY_NAME,
                VERSION,
                HDRSIZE,
                MAXATTR,
                OPS,
                MCAST_GROUPS,
                POLICY,
                OP_POLICY,
                OP,
            };
        };
        const MCastAttr = extern struct {
            len: u16, //not including padding
            type: MCAST_GRP,
            // payload
            // and padding to reach a multiple of 4 bytes
            const MCAST_GRP = enum(u16) {
                UNSPEC,
                NAME,
                ID,
            };
        };

        fn init() !Netlink {
            const nl_sock = try std.posix.socket(
                linux.AF.NETLINK,
                linux.SOCK.RAW,
                linux.NETLINK.GENERIC,
            );
            const NETLINK_EXT_ACK = 11;
            const NETLINK_CAP_ACK = 10;
            // enable extended acks on this socket
            try std.posix.setsockopt(nl_sock, linux.SOL.NETLINK, NETLINK_EXT_ACK, &.{ 1, 0, 0, 0 });
            // don't send payload if an error occurs
            try std.posix.setsockopt(nl_sock, linux.SOL.NETLINK, NETLINK_CAP_ACK, &.{ 1, 0, 0, 0 });
            return .{ .sock = .{ .handle = nl_sock } };
        }
        fn deinit(nl: Netlink) void {
            nl.sock.close();
        }

        const msg_size = @max(std.heap.pageSize(), 8192);

        /// blocking.. after this the socket can be polled for acpi events
        /// and the socket will be non-blocking
        fn subscribeToAcpiEvents(nl: *Netlink) !void {
            var read_buf: [msg_size]u8 = undefined;
            var sock_reader = nl.sock.reader(&read_buf);
            const r = &sock_reader.interface;

            var write_buf: [msg_size]u8 = undefined;
            var sock_writer = nl.sock.writer(&write_buf);
            const w = &sock_writer.interface;

            const name = "acpi_event";

            const GENL_ID_CTRL = 0x10;
            try w.writeStruct(Header{
                .len = @sizeOf(Header) + @sizeOf(Generic) + @sizeOf(CtrlAttr) + name.len + 1 + 1,
                .type = GENL_ID_CTRL,
                .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
                .seq = nl.seq,
                .pid = 0,
            }, native_endian);
            nl.seq += 1;

            const CTRL_CMD_GETFAMILY = 3;
            try w.writeStruct(Generic{ .cmd = CTRL_CMD_GETFAMILY }, native_endian);

            try w.writeStruct(CtrlAttr{
                .len = @sizeOf(CtrlAttr) + name.len + 1,
                .type = .FAMILY_NAME,
            }, native_endian);
            // name should be null terminated and the message should have an alignment of 4
            try w.print("{s}\x00\x00", .{name});
            try w.flush();

            var group_id: ?[4]u8 = null;

            while (true) {
                const header = try r.takeStruct(Header, native_endian);
                const msg_len = std.mem.alignForward(usize, header.len - @sizeOf(Header), 4);
                var msg_r: std.Io.Reader = .fixed(try r.take(msg_len));

                switch (header.type) {
                    1, 4 => unreachable, // NOOP, and OVERRUN (not used)
                    2 => { // ERROR/ACK
                        const err = try msg_r.takeStruct(Error, native_endian);
                        if (err.err == 0) break; //success ACK
                        const NLM_F_ACK_TLVS = 0x200;
                        if (header.flags & NLM_F_ACK_TLVS > 0) {
                            std.debug.print("extra info exists\n", .{});
                        }
                        fatal("netlink error: {any}\n{any}", .{ header, err });
                    },
                    3 => unreachable, // DONE, unreachable since dump isnt used?
                    else => {}, // not a control message
                }

                msg_r.toss(@sizeOf(Generic));

                while (msg_r.takeStruct(CtrlAttr, native_endian)) |attr| {
                    const attr_len = std.mem.alignForward(usize, attr.len - @sizeOf(CtrlAttr), 4);
                    var attr_r: std.Io.Reader = .fixed(try msg_r.take(attr_len));
                    if (attr.type == .MCAST_GROUPS) {
                        attr_r.toss(@sizeOf(MCastAttr)); // skip first attr
                        while (attr_r.takeStruct(MCastAttr, native_endian)) |grp_attr| {
                            const len_with_padding = std.mem.alignForward(usize, grp_attr.len - @sizeOf(MCastAttr), 4);
                            const grp_val = try attr_r.take(len_with_padding);
                            if (grp_attr.type == .ID) group_id = grp_val[0..4].*;
                        } else |err| if (err != error.EndOfStream) return err;
                    }
                } else |err| if (err != error.EndOfStream) return err;
            }

            const NETLINK_ADD_MEMBERSHIP = 1;
            try std.posix.setsockopt(
                nl.sock.handle,
                linux.SOL.NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                if (group_id) |gi| &gi else return error.NoGroupIdFound,
            );

            var flags = try std.posix.fcntl(nl.sock.handle, linux.F.GETFL, 0);
            flags |= 1 << @bitOffsetOf(linux.O, "NONBLOCK");
            _ = try std.posix.fcntl(nl.sock.handle, linux.F.SETFL, flags);
        }

        const AcStatus = enum { offline, online, unknown };

        /// call when events are ready to be read
        /// after subscribing
        fn getAcStatus(nl: *Netlink) !?AcStatus {
            var read_buf: [msg_size]u8 = undefined;
            var sock_reader = nl.sock.reader(&read_buf);
            const r = &sock_reader.interface;

            var status: ?AcStatus = null;

            while (true) {
                const to_skip = @sizeOf(Header) + @sizeOf(Generic) + @sizeOf(CtrlAttr);
                r.fill(to_skip + @sizeOf(AcpiGenlEvent)) catch break;
                r.discardAll(to_skip) catch unreachable;
                const event: *AcpiGenlEvent = @alignCast(r.takeStructPointer(AcpiGenlEvent) catch unreachable);
                if (event.acStatus()) |new_status| {
                    status = new_status;
                }
            }
            return if (sock_reader.err.? == error.WouldBlock) status else sock_reader.err.?;
        }

        // defined in linux kernel src
        // linux-src/drivers/acpi/event.c
        const AcpiGenlEvent = extern struct {
            device_class: [20]u8,
            bus_id: [16]u8, // really 15, but becomes 16 with padding.
            type: u32,
            data: u32,

            comptime {
                std.debug.assert(@alignOf(@This()) == 4);
            }

            fn acStatus(ae: *const AcpiGenlEvent) ?AcStatus {
                const class = "ac_adapter";
                if (!std.mem.eql(u8, class, ae.device_class[0..class.len])) return null;
                // linux-src/drivers/acpi/ac.c
                return switch (ae.data) {
                    0x00 => .offline,
                    0x01 => .online,
                    0xff => .unknown,
                    else => unreachable,
                };
            }
        };
    };
};
