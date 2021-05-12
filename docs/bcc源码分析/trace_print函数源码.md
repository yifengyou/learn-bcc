# trace_print函数源码



```
    def trace_print(self, fmt=None):
        """trace_print(self, fmt=None)

        Read from the kernel debug trace pipe and print on stdout.
        If fmt is specified, apply as a format string to the output. See
        trace_fields for the members of the tuple
        example: trace_print(fmt="pid {1}, msg = {5}")
        """

        while True:
            if fmt:
                fields = self.trace_fields(nonblocking=False)
                if not fields: continue
                line = fmt.format(*fields)
            else:
                line = self.trace_readline(nonblocking=False)
            print(line)
            sys.stdout.flush()
```

```
    def trace_readline(self, nonblocking=False):
        """trace_readline(nonblocking=False)

        Read from the kernel debug trace pipe and return one line
        If nonblocking is False, this will block until ctrl-C is pressed.
        """

        trace = self.trace_open(nonblocking)

        line = None
        try:
            line = trace.readline(1024).rstrip()
        except IOError:
            pass
        return line
```

这里 trace_open 打开的是 ```/sys/kernel/debug/tracing/trace_pipe```

```
TRACEFS = "/sys/kernel/debug/tracing"
```

```
    def trace_open(self, nonblocking=False):
        """trace_open(nonblocking=False)

        Open the trace_pipe if not already open
        """
        if not self.tracefile:
            self.tracefile = open("%s/trace_pipe" % TRACEFS, "rb")
            if nonblocking:
                fd = self.tracefile.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return self.tracefile
```


trace_print最终其实就是非阻塞打开了/sys/kernel/debug/tracing/trace_pipe，效果与一毛一样

```
tail -f /sys/kernel/debug/tracing/trace_pipe
```

















---
