def port: type == "number" and floor == . and . >= 1 and . <= 65535;
def text: type == "string" and length > 0 and (test("[\\x00-\\x1f\\x7f]") | not);
def private_cidr:
  if . == "::1/128" or . == "fc00::/7" or . == "fe80::/10" then true
  elif type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$") then
    split("/") as $p | ($p[0] | split(".") | map(tonumber)) as $a | ($p[1]|tonumber) as $n |
    all($a[]; . >= 0 and . <= 255) and $n <= 32 and
    (($a[0] == 10 and $n >= 8) or ($a[0] == 127 and $n >= 8) or
     ($a[0] == 172 and $a[1] >= 16 and $a[1] <= 31 and $n >= 12) or
     ($a[0] == 192 and $a[1] == 168 and $n >= 16))
  else false end;
def safe_domain:
  . as $d | type == "string" and test("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$") and
  (contains("..")|not) and
  (["anthropic.com","claude.ai","claude.com","claudeusercontent.com","claudemcpcontent.com","api4.ipify.org","api6.ipify.org"] |
   all(.[]; . as $protected | . != $d and (endswith("." + $d)|not) and ($d|endswith("." + $protected)|not)));
(.server | text and test("^[A-Za-z0-9][A-Za-z0-9.:-]*$")) and
(.ssh_port | port) and (.proxy_port | port) and (.user | text) and (.key | text) and
(.host_key | type == "string" and test("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,2}$")) and
(.domains | type == "array" and all(.[]; safe_domain)) and
(.cidrs | type == "array" and all(.[]; private_cidr))
