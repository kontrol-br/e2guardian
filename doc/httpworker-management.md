# HTTP worker management improvements

Version 5.3.8 introduced fixes to prevent the HTTP worker pool statistics from
remaining saturated after bursts of traffic. The core of the change is the
`BusyChildGuard` helper that wraps the lifetime of the thread's work on a
connection. When the guard object is constructed it increments
`dystat->busychildren`; when the guard leaves scope—whether because the
connection completed, returned early, or raised an exception—it automatically
decrements the counter. This mirrors the period in which the worker is actually
busy and makes it impossible to forget the decrement on an unusual error path.

Because the guard's destructor runs even if `handlePeer()` throws, the worker
count now falls back to the idle value as soon as every outstanding request has
been accounted for. In previous releases, any early `return` or exception inside
`handlePeer()` could skip the manual decrement and leave the counter pinned at
the configured maximum, even though the threads were no longer processing
traffic.

Worker sockets are also managed through `std::unique_ptr` so that file
descriptors are released even on unexpected termination paths.

These changes keep the `dstats` output aligned with the actual load and avoid
artificial exhaustion of the worker pool that previously required hours to
recover.

## Rebuilding and testing on FreeBSD

To rebuild the project on FreeBSD (including the pfSense port), install the
usual build dependencies and run:

```sh
./autogen.sh
./configure --with-proxyuser=e2guardian --with-proxygroup=e2guardian \
    --enable-icap=yes --enable-commandline=yes --enable-email=yes
make
make check
```

Adjust the configuration flags to match your deployment. After building, deploy
`src/e2guardian` to your testing environment and monitor `log/dstats` to verify
that the `busychildren` count returns to the idle level once traffic subsides.
