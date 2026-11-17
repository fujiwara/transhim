# Compact, human-readable view of a capture file:
#   jq -r -f compat/summary.jq testdata/capture/ceph-v20.2.5.jsonl
def short: if . == null or . == "" then "-" elif length > 100 then .[0:100] + "…" else . end;
if .mark then "# " + .mark
else "    \(.request.method) \(.request.path)  \(.request.body | short)  => \(.response.status // "no response")"
end
