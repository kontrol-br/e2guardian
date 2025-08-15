# File descriptor leak test

This manual test verifies that `Socket::accept` closes file descriptors on error.

1. Build and run e2guardian normally.
2. In another shell, reduce the available descriptor limit and create many client
   connections to force `accept` or `fcntl` failures:
   ```bash
   ulimit -n 10
   for i in {1..20}; do nc localhost 8080 & done
   wait
   ```
3. Inspect the e2guardian logs.  Each failure should include a message such as
   `accept4 failed` or `fcntl failed` and no "leaked fd" warnings should appear.
4. Optionally monitor the process with `lsof` to confirm that descriptor counts
   return to baseline after the test.
