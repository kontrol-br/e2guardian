# Troubleshooting: all users suddenly matching the first IP auth group

If e2guardian starts placing every client into the first filter group (for
example `SEM-BLOQUEIO`) until service restart, check the items below.

## 1) `usexforwardedfor` can collapse all users into one source IP

With the `ip` auth plugin, when `usexforwardedfor=on`, e2guardian prioritizes
the IP extracted from `X-Forwarded-For` before socket/client fallback values.
If all requests arrive with the same forwarded IP (or a spoofed header), every
user maps to the same group.

## 2) Catch-all subnets in `ipgroups` win by order

Subnet entries are evaluated in list order, and the first match wins. A broad
entry such as `0.0.0.0/0=1` near the top will effectively send everyone to a
single group.

## 2b) Group can be overridden after IP auth (`setgroup`)

Even when IP auth identifies users correctly, StoryBoard rules can later force
another filter group via `setgroup`. In this case, logs still show different
user IPs, but the final group column becomes the same for many/all requests.

Recent hardening ignores `setgroup` when it is used without a list-derived
result (for example, attached to non-list states), reducing accidental
"sticky group" behavior from stale intermediate values.

## 3) Invalid group `0` in `ipgroups`

`ipgroups` values are 1-based (`1..filtergroups`). Group `0` is invalid and
must be rejected. A typo like `192.168.1.10=0` can unintentionally force a
match to the first group if not validated strictly.

## Fast validation checklist

1. Confirm `authplugins/ip.conf` and `lists/authplugins/ipgroups` did not
   change unexpectedly.
2. If `usexforwardedfor=on`, verify `xforwardedforfilterip` is explicitly set
   only for trusted upstream proxies.
3. Search `ipgroups` for `=0`, `group0`, and broad CIDRs/ranges.
4. Enable auth debug logs and compare chosen user IP vs. peer IP/XFF.

## Operational note

Recent code logs a warning when `usexforwardedfor=on` and
`xforwardedforfilterip` is empty, because this trusts `X-Forwarded-For` from
all peers and can collapse user identification unexpectedly.
