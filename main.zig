const std = @import("std");
const builtin = @import("builtin");

const fatal = std.process.fatal;

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

    var env_map = try std.process.getEnvMap(alc);
    defer env_map.deinit();

    const run_dir = env_map.get("XDG_RUNTIME_DIR") orelse fatal("XDG_RUNTIME_DIR not in env", .{});
    const log_path = try std.mem.join(alc, "/", &.{ run_dir, log_file_name });
    defer alc.free(log_path);
    const socket_path = try std.mem.join(alc, "/", &.{ run_dir, status_socket_name });
    defer alc.free(socket_path);

    switch (try Args.parse(args_input)) {
        .log => try printLog(alc, log_path),
        .send => |args| try sendOutputToDaemon(alc, args, socket_path),
        .start => try startDaemon(alc, socket_path, log_path),
    }
}

fn printLog(alc: std.mem.Allocator, log_path: []const u8) !void {
    const log_file = std.fs.openFileAbsolute(log_path, .{}) catch |err| switch (err) {
        error.FileNotFound => fatal("could not find log-file: {s}, it is usually available as long as the daemon is running", .{log_path}),
        else => return err,
    };
    defer log_file.close();

    const tzfat = try std.fs.openFileAbsolute("/etc/localtime", .{});
    defer tzfat.close();

    var tz = try std.tz.Tz.parse(alc, tzfat.reader());
    defer tz.deinit();

    var i: usize = tz.transitions.len - 1;
    const current_timestamp = std.time.timestamp();
    const offset_secs = while (i > 0) : (i -= 1) {
        const t = tz.transitions[i];
        if (current_timestamp > t.ts) break t.timetype.offset;
    } else unreachable;

    const w = std.io.getStdOut().writer();
    const r = log_file.reader();
    while (true) {
        const log_timestamp: i64 = @bitCast(r.readBytesNoEof(@sizeOf(i64)) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        });

        const ep_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(log_timestamp + offset_secs) };
        const ep_day = ep_secs.getEpochDay();
        const year_day = ep_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_secs = ep_secs.getDaySeconds();

        const year = year_day.year;
        const month = month_day.month.numeric();
        const day = month_day.day_index + 1;
        const hour = day_secs.getHoursIntoDay();
        const minute = day_secs.getMinutesIntoHour();
        const second = day_secs.getSecondsIntoMinute();

        const fmt = "[{:0>4}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2}]  ";
        const arg = .{ year, month, day, hour, minute, second };
        try w.print(fmt, arg);

        try r.streamUntilDelimiter(w, '\n', 516);
        try w.writeByte('\n');
    }
}

fn sendOutputToDaemon(alc: std.mem.Allocator, args: Args.Send, socket_path: []const u8) !void {
    const cmd = try std.mem.join(alc, " ", args.cmd);
    defer alc.free(cmd);

    const stream = std.net.connectUnixSocket(socket_path) catch |err| switch (err) {
        error.FileNotFound => fatal("cannot connect to daemon, make sure it is started with --start", .{}),
        else => return err,
    };
    defer stream.close();

    var child = std.process.Child.init(&.{ "sh", "-c", cmd }, alc);
    child.stdout_behavior = .Pipe;
    try child.spawn();
    const child_out = child.stdout.?.reader();

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const max_len = 256;
    const prefix_len = if (args.name) |n| (try std.fmt.bufPrint(&buf, "{s}: ", .{n})).len else 0;
    if (prefix_len >= max_len) fatal("command name too long", .{});

    while (true) {
        fbs.pos = prefix_len;

        child_out.streamUntilDelimiter(fbs.writer(), '\n', max_len - prefix_len) catch |err| switch (err) {
            error.EndOfStream => break,
            error.StreamTooLong => {},
            else => return err,
        };
        try fbs.writer().writeAll("\n");
        try stream.writeAll(fbs.getWritten());
    }
    // on end of stream, send last output, even if it doesnt end with \n
    if (fbs.pos > prefix_len) {
        if (fbs.buffer[fbs.pos - 1] != '\n') try fbs.writer().writeAll("\n");
        try stream.writeAll(fbs.getWritten());
    }
    _ = try child.wait();
}

fn startDaemon(alc: std.mem.Allocator, socket_path: []const u8, log_path: []const u8) !void {
    var state = try DaemonState.init(alc, socket_path, log_path);
    defer state.deinit(socket_path, log_path);

    try state.epoll.addEvent(state.signal_fd, .{
        .callback = DaemonState.signalCallback,
        .state = &state,
    });

    try state.epoll.addEvent(state.server.stream.handle, .{
        .callback = DaemonState.serverAcceptCallback,
        .state = &state,
    });

    try state.epoll.addEvent(state.battery.ac_netlink.sock.handle, .{
        .callback = DaemonState.acCallback,
        .state = &state,
    });

    try state.epoll.addEvent(state.battery.timer_fd, .{
        .callback = DaemonState.batteryCapacityCallback,
        .state = &state,
    });

    if (state.datetime.inotify) |i| {
        try state.epoll.addEvent(i.file.handle, .{
            .callback = DaemonState.maybeUpdateTimezoneCallback,
            .state = &state,
        });
    }

    try state.epoll.addEvent(state.datetime.timer_fd, .{
        .callback = DaemonState.getTimeCallback,
        .state = &state,
    });

    try state.epoll.run();
}

const DaemonState = struct {
    alc: std.mem.Allocator,

    signal_fd: std.posix.fd_t,

    server: std.net.Server,
    log_file: std.fs.File,

    epoll: Epoll,

    message: std.BoundedArray(u8, 256) = .{},

    audio: Audio,

    battery: Battery,

    datetime: DateTime,
    time: std.BoundedArray(u8, 32) = .{},

    const Self = @This();

    fn init(alc: std.mem.Allocator, socket_path: []const u8, log_path: []const u8) !Self {
        // handle common signals, so temporary files (log and socket) get
        // removed when the process gets terminated (most of the time)
        // usually, the process isn't supposed to terminate until you power off though
        // but sending these signals is the only way to shut down the daemon as well
        // mostly debugging convenience
        // but also helpful when reloading the sway config?
        // TODO: check if true
        var mask = std.posix.empty_sigset;
        std.os.linux.sigaddset(&mask, std.os.linux.SIG.INT);
        std.os.linux.sigaddset(&mask, std.os.linux.SIG.TERM);
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

        const log_file = try std.fs.createFileAbsolute(log_path, .{});
        errdefer std.fs.deleteFileAbsolute(log_path) catch unreachable;
        errdefer log_file.close();

        var epoll = try Epoll.init(alc);
        errdefer epoll.deinit();

        var audio = try Audio.init();
        errdefer audio.deinit();

        var battery = try Battery.init();
        errdefer battery.deinit();

        var datetime = try DateTime.init(alc);
        errdefer datetime.deinit();

        try writeStatusInit();

        return .{
            .alc = alc,
            .signal_fd = signal_fd,
            .server = server,
            .log_file = log_file,
            .epoll = epoll,
            .audio = audio,
            .battery = battery,
            .datetime = datetime,
        };
    }

    fn deinit(self: *Self, socket_path: []const u8, log_path: []const u8) void {
        std.posix.close(self.signal_fd);
        self.server.deinit();

        std.fs.deleteFileAbsolute(socket_path) catch unreachable;
        std.fs.deleteFileAbsolute(log_path) catch unreachable;
        self.log_file.close();

        self.epoll.deinit();
        self.audio.deinit();
        self.battery.deinit();
        self.datetime.deinit();
    }

    /// header for swaybar-protocol
    fn writeStatusInit() !void {
        const w = std.io.getStdOut().writer();
        try w.writeAll("{\"version\":1}\n[");
    }

    fn writeStatus(self: Self) !void {
        const w = std.io.getStdOut().writer();
        try w.print("[{{\"full_text\":\"{s} \"}}," ++
            // pango markup to have volume struck out when muted
            "{{\"markup\":\"pango\",\"full_text\": \" ({s}{s}{d:.2}{s}) {s}[{}%] {s}\"}}],", .{
            self.message.slice(),
            switch (self.audio.sink) {
                .bluetooth => "bt: ",
                .speakers => "",
            },
            if (self.audio.muted) "<s>" else "",
            self.audio.volume,
            if (self.audio.muted) "</s>" else "",
            switch (self.battery.ac_status) {
                .online => "^",
                .offline => "",
                .unknown => "?",
            },
            self.battery.capacity,
            self.time.slice(),
        });
    }

    fn signalCallback(_: *anyopaque, _: std.posix.fd_t) !void {
        // returning an error will make the epoll loop exit,
        // and the deferred clean up functions will be called
        return error.RecievedIntOrTermSignal;
    }

    fn serverAcceptCallback(data: *anyopaque, _: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));
        const conn = try self.server.accept();
        errdefer conn.stream.close();
        try self.epoll.addEvent(conn.stream.handle, .{
            .callback = connectionReadCallback,
            .state = self,
        });
    }

    fn connectionReadCallback(data: *anyopaque, conn_fd: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));
        var fbs = std.io.fixedBufferStream(&self.message.buffer);
        const reader = (std.net.Stream{ .handle = conn_fd }).reader();
        // this will not block long, since every message sent by the sender
        // has to end in a newline, and is sent in full
        reader.streamUntilDelimiter(fbs.writer(), '\n', fbs.buffer.len) catch |err| switch (err) {
            error.EndOfStream => {
                try self.epoll.removeEvent(conn_fd);
                return;
            },
            else => return err,
        };
        self.message.len = fbs.pos;
        try self.writeStatus();
        // logging
        const timestamp = std.time.timestamp();
        try self.log_file.writeAll(&std.mem.toBytes(timestamp));
        try self.log_file.writeAll(self.message.slice());
        try self.log_file.writeAll("\n");
    }

    fn acCallback(data: *anyopaque, _: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));
        self.battery.ac_status = try self.battery.ac_netlink.getAcStatus() orelse return;
        try self.writeStatus();
    }

    fn batteryCapacityCallback(data: *anyopaque, _: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));

        var buf: [8]u8 = undefined;
        _ = try std.posix.read(self.battery.timer_fd, &buf);

        self.battery.capacity = try Battery.getNewCapacity(self.battery.cap_files);
        try self.writeStatus();
    }

    fn getTimeCallback(data: *anyopaque, _: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));

        var buf: [8]u8 = undefined;
        _ = try std.posix.read(self.datetime.timer_fd, &buf);

        self.time.len = self.datetime.getTime(&self.time.buffer).len;
        try self.writeStatus();
    }

    fn maybeUpdateTimezoneCallback(data: *anyopaque, _: std.posix.fd_t) !void {
        const self: *DaemonState = @alignCast(@ptrCast(data));
        if (try self.datetime.maybeUpdateTimezone()) {
            self.time.len = self.datetime.getTime(&self.time.buffer).len;
            try self.writeStatus();
        }
    }
};

const Epoll = struct {
    epoll_fd: i32,
    events: EventMap,

    const EventMap = std.AutoHashMap(std.posix.fd_t, Event);

    const Event = struct {
        callback: *const fn (*anyopaque, std.posix.fd_t) anyerror!void,
        state: *anyopaque,
    };

    const EPOLL = std.os.linux.EPOLL;

    fn init(alc: std.mem.Allocator) !Epoll {
        return .{
            .epoll_fd = try std.posix.epoll_create1(0),
            .events = EventMap.init(alc),
        };
    }

    /// does not close event file descriptors
    fn deinit(self: *Epoll) void {
        std.posix.close(self.epoll_fd);
        self.events.deinit();
    }

    /// Event.state must be freed by caller when done
    /// should i use EPOLL.ET?
    fn addEvent(self: *Epoll, fd: std.posix.fd_t, event: Event) !void {
        var ev: std.os.linux.epoll_event = .{
            .data = .{ .fd = fd },
            .events = EPOLL.IN,
        };
        try std.posix.epoll_ctl(self.epoll_fd, EPOLL.CTL_ADD, fd, &ev);
        try self.events.putNoClobber(fd, event);
    }

    fn removeEvent(self: *Epoll, fd: std.posix.fd_t) !void {
        std.debug.assert(self.events.remove(fd));
        try std.posix.epoll_ctl(self.epoll_fd, EPOLL.CTL_DEL, fd, null);
        std.posix.close(fd);
    }

    fn run(self: Epoll) !void {
        const wait_max_events = 16;
        var events: [wait_max_events]std.os.linux.epoll_event = undefined;
        while (true) {
            const n_fds = std.posix.epoll_wait(self.epoll_fd, &events, -1);
            for (events[0..n_fds]) |ev| {
                const event = self.events.get(ev.data.fd) orelse unreachable;
                try event.callback(event.state, ev.data.fd);
            }
        }
    }
};

const Audio = struct {
    sink: enum {
        bluetooth,
        speakers,
    },
    muted: bool,
    volume: f16,

    fn init() !Audio {
        return Audio{ .sink = .bluetooth, .muted = true, .volume = 0.3333 };
    }
    fn deinit(self: Audio) void {
        _ = self;
    }
};

const Battery = struct {
    cap_files: [2]?std.fs.File,
    capacity: u8,

    ac_netlink: Netlink,
    ac_status: Netlink.AcStatus,
    // timer for reading current battery capacity
    timer_fd: i32,

    fn init() !Battery {
        var nl = try Netlink.init();
        errdefer nl.deinit();

        try nl.subscribeToAcpiEvents();
        const ac = try std.fs.openFileAbsolute("/sys/class/power_supply/AC/online", .{});
        defer ac.close();

        const ac_status: Netlink.AcStatus = switch (try ac.reader().readByte()) {
            0 => .offline,
            1 => .online,
            else => .unknown,
        };

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
        var buf: [4]u8 = undefined;
        var cap: u8 = 0;
        var count: u8 = 0;
        for (files) |bat| {
            if (bat) |b| {
                count += 1;
                // need to read from beginning of file each time
                const n = try b.preadAll(&buf, 0);
                // n-1 to remove the newline
                cap += try std.fmt.parseInt(u8, buf[0 .. n - 1], 10);
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
        const Attr = extern struct {
            len: u16, //not including padding
            type: u16,
            // payload
            // and padding to reach a multiple of 4 bytes
        };
        const CTRL_ATTR = enum {
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
        fn deinit(self: Netlink) void {
            self.sock.close();
        }

        const msg_size = @max(std.heap.pageSize(), 8192);

        /// blocking.. after this the socket can be polled for acpi events
        /// and the socket will be non-blocking
        fn subscribeToAcpiEvents(self: *Netlink) !void {
            var buf: [msg_size]u8 = undefined;
            var msg = std.io.fixedBufferStream(&buf);
            // skip header, will be set last to get correct length
            try msg.seekBy(@sizeOf(Header));

            const CTRL_CMD_GETFAMILY = 3;
            try msg.writer().writeStruct(Generic{ .cmd = CTRL_CMD_GETFAMILY });

            const name = "acpi_event";
            try msg.writer().writeStruct(Attr{
                .len = @sizeOf(Attr) + name.len + 1,
                .type = @intFromEnum(CTRL_ATTR.FAMILY_NAME),
            });
            try msg.writer().writeAll(name);
            // should be null terminated
            try msg.writer().writeByte(0);
            // pad to alignment of 4
            try msg.writer().writeByte(0);

            const GENL_ID_CTRL = 0x10;
            buf[0..@sizeOf(Header)].* = @bitCast(Header{
                .len = @intCast(msg.pos),
                .type = GENL_ID_CTRL,
                .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
                .seq = self.seq,
                .pid = 0,
            });
            self.seq += 1;

            try self.sock.writeAll(msg.getWritten());

            var group_id: ?u32 = null;
            outer: while (true) {
                const n = try self.sock.read(&buf);
                // now msg contains the last recieved message
                msg.reset();
                while (msg.pos < n) {
                    const msg_start = msg.pos;
                    const header = try msg.reader().readStruct(Header);
                    const NLM_F_ACK_TLVS = 0x200;
                    switch (header.type) {
                        // NOOP, and OVERRUN (not used)
                        1, 4 => unreachable,
                        // ERROR/ACK
                        2 => {
                            const err = try msg.reader().readStruct(Error);
                            if (err.err == 0) break :outer;
                            if (header.flags & NLM_F_ACK_TLVS > 0) {
                                std.debug.print("extra info exists\n", .{});
                            }
                            fatal("netlink error: {any}\n{any}", .{ header, err });
                        },
                        // DONE
                        3 => unreachable, // since dump isnt used?
                        // not a control message
                        else => {},
                    }
                    _ = try msg.reader().readStruct(Generic);
                    while (msg.pos < msg_start + header.len) {
                        const attr = try msg.reader().readStruct(Attr);
                        const attr_type: CTRL_ATTR = @enumFromInt(attr.type);
                        const len = attr.len - @sizeOf(Attr);
                        const val = buf[msg.pos..][0..len];
                        if (attr_type == .MCAST_GROUPS) {
                            const MCAST_GRP = enum {
                                UNSPEC,
                                NAME,
                                ID,
                            };
                            // first attr is useless? so skip it
                            var i: usize = @sizeOf(Attr);
                            while (i < len) {
                                const grp_attr: *Attr = @alignCast(@ptrCast(val[i..][0..@sizeOf(Attr)]));
                                i += @sizeOf(Attr);
                                const grp_val = val[i..][0 .. grp_attr.len - @sizeOf(Attr)];
                                const grp_attr_type: MCAST_GRP = @enumFromInt(grp_attr.type);
                                if (grp_attr_type == .ID) group_id = @bitCast(grp_val[0..4].*);
                                i += std.mem.alignForward(usize, grp_val.len, 4);
                            }
                        }
                        const off = std.mem.alignForward(i64, len, 4);
                        try msg.seekBy(off);
                    }
                }
            }
            const NETLINK_ADD_MEMBERSHIP = 1;
            try std.posix.setsockopt(
                self.sock.handle,
                linux.SOL.NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                std.mem.asBytes(&(group_id orelse return error.NoGroupIdFound)),
            );

            var flags = try std.posix.fcntl(self.sock.handle, linux.F.GETFL, 0);
            flags |= 1 << @bitOffsetOf(linux.O, "NONBLOCK");
            _ = try std.posix.fcntl(self.sock.handle, linux.F.SETFL, flags);
        }

        const AcStatus = enum { offline, online, unknown };

        /// call when events are ready to be read
        /// after subscribing
        fn getAcStatus(self: Netlink) !?AcStatus {
            var buf: [msg_size]u8 = undefined;
            var status: ?AcStatus = null;

            while (true) {
                const n = self.sock.read(&buf) catch |err| switch (err) {
                    error.WouldBlock => return status,
                    else => return err,
                };
                var i: usize = 0;
                while (i < n) {
                    // skip all of these
                    // should maybe check header for errors?
                    i += @sizeOf(Header) + @sizeOf(Generic) + @sizeOf(Attr);

                    const event: *AcpiGenlEvent = @alignCast(@ptrCast(buf[i..][0..@sizeOf(AcpiGenlEvent)]));
                    i += @sizeOf(AcpiGenlEvent);
                    if (event.acStatus()) |new_status| {
                        status = new_status;
                    }
                }
            }
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

            fn acStatus(self: AcpiGenlEvent) ?AcStatus {
                const class = "ac_adapter";
                if (!std.mem.eql(u8, class, self.device_class[0..class.len])) return null;
                // linux-src/drivers/acpi/ac.c
                return switch (self.data) {
                    0x00 => .offline,
                    0x01 => .online,
                    0xff => .unknown,
                    else => unreachable,
                };
            }
        };
    };
};

const DateTime = struct {
    /// if null, the timezone was set by an environment variable
    /// and cannot change dynamically
    inotify: ?struct {
        /// when readable, a new timezone should maybe be loaded
        file: std.fs.File,
        watch_descriptor: i32,
    } = null,
    tz: std.tz.Tz,

    timer_fd: i32,

    fn init(alc: std.mem.Allocator) !DateTime {
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

        const tzfat = try std.fs.openFileAbsolute("/etc/localtime", .{});
        defer tzfat.close();

        var tz = try std.tz.Tz.parse(alc, tzfat.reader());
        errdefer tz.deinit();

        const IN_NONBLOCK = 0o00004000;
        const ino_file: std.fs.File = .{ .handle = try std.posix.inotify_init1(IN_NONBLOCK) };
        errdefer ino_file.close();

        const IN_CREATE = 0x00000100; // file created (symlink created)
        const IN_MOVED_TO = 0x00000080; // file renamed to event.name
        const mask = IN_CREATE | IN_MOVED_TO;
        const tz_wd = try std.posix.inotify_add_watch(ino_file.handle, "/etc", mask);

        return .{
            .tz = tz,
            .inotify = .{ .file = ino_file, .watch_descriptor = tz_wd },
            .timer_fd = timer_fd,
        };
    }

    fn deinit(self: *DateTime) void {
        if (self.inotify) |i| i.file.close();
        self.tz.deinit();
        std.posix.close(self.timer_fd);
    }

    const InotifyEvent = std.os.linux.inotify_event;

    /// returns true if timezone was updated
    fn maybeUpdateTimezone(self: *DateTime) !bool {
        const ino = self.inotify.?;
        var did_update = false;
        // need to read to a buffer big enough to hold the entire event,
        // otherwise read returns INVAL
        var buf: [@sizeOf(InotifyEvent) + std.os.linux.NAME_MAX + 1]u8 = undefined;
        while (true) {
            const read_bytes = ino.file.reader().read(&buf) catch |err| switch (err) {
                error.WouldBlock => return did_update,
                else => return err,
            };
            const event: InotifyEvent = @bitCast(buf[0..@sizeOf(InotifyEvent)].*);

            std.debug.assert(read_bytes == @sizeOf(InotifyEvent) + event.len);
            if (event.wd == -1) return error.EventQueueOverflowed;
            std.debug.assert(event.wd == ino.watch_descriptor);

            const name_buf = buf[@sizeOf(InotifyEvent)..][0..event.len];

            const name = "localtime";
            if (name_buf.len <= name.len or name_buf[name.len] != 0) continue;
            for (name, 0..) |b, i| if (b != name_buf[i]) continue;

            const tzfat = try std.fs.openFileAbsolute("/etc/localtime", .{});
            defer tzfat.close();

            const tz = try std.tz.Tz.parse(self.tz.allocator, tzfat.reader());
            self.tz.deinit();
            self.tz = tz;

            did_update = true;
        }
    }

    fn getTime(self: DateTime, buf: *[32]u8) []const u8 {
        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
        const timestamp_secs = ts.sec;

        var i: usize = self.tz.transitions.len - 1;
        const tz_seconds = while (i > 0) : (i -= 1) {
            const t = self.tz.transitions[i];
            if (timestamp_secs > t.ts) break t.timetype.offset + timestamp_secs;
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
        return std.fmt.bufPrint(buf, fmt, arg) catch unreachable;
    }
};
