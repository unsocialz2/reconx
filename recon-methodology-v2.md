# Bug Bounty Recon Methodology v2

> ملحوظة: الأدوات المتعددة لنفس الغرض (زي 5 طرق مختلفة لعمل subdomain enum) اتسابت عن قصد — الهدف إنك تستخدم أكتر من مصدر عشان الكفرة تكون أعلى، وبعدين نعمل merge + dedupe في نهاية كل مرحلة. الأدوات دي كلها معروفة وعامة (subfinder, httpx, nuclei...إلخ) ومفيش فيها تفاصيل استغلال جديدة، بس اتنظمت كـ pipeline مرحلي بدل ما تكون أكوام أوامر متفرقة.

---

## Phase 0 — Setup

```bash
export TARGET="example.com"
export OUTDIR="recon_$TARGET"
mkdir -p $OUTDIR/{subs,resolved,alive,urls,js,params,dirs,vulns,cloud,ports,loot}
cd $OUTDIR
```

**معايير موحدة عبر الأدوات كلها (بدل ما كل أداة بمعدل عشوائي):**
- Threads: `50-80` للـ HTTP-based tools (httpx, ffuf, dirsearch)
- Rate: `1000-2000` للـ DNS resolution (puredns, dnsx, massdns)
- استخدم `-resume` أو flag مشابه في أي أداة بتدعمه (ffuf, dirsearch, feroxbuster) عشان لو السكان اتقطع في target كبير متبدأش من الأول

**Wildcard Detection (لازم قبل أي bruteforce):**
```bash
dig random12345.$TARGET
puredns bruteforce wordlist.txt $TARGET -r resolvers.txt --wildcard-tests 50
```

---

## Phase 1 — Subdomain Enumeration

### 1.1 Passive
```bash
subfinder -d $TARGET -all -recursive -o subs/subfinder.txt
echo $TARGET | assetfinder -subs-only > subs/assetfinder.txt
amass enum -d $TARGET -o subs/amass.txt
findomain -t $TARGET -u subs/findomain.txt
chaos -d $TARGET -o subs/chaos.txt
github-subdomains -d $TARGET -t $GITHUB_TOKEN -o subs/github.txt

curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
| jq -r '.[].name_value' | sed 's/\*\.//g' \
| tr '\n' ',' | tr ',' '\n' \
| grep -oE "[A-Za-z0-9._-]+\.${TARGET//./\\.}" | sort -u >> subs/crtsh.txt
```

### 1.2 Active / Bruteforce
```bash
puredns bruteforce wordlist.txt $TARGET -r resolvers.txt -w subs/puredns.txt
dnsx -silent -d $TARGET -w wordlist.txt > subs/dnsx.txt
```

### 1.3 Permutation (كان ناقص خالص — ده أهم إضافة)
بيولّد subdomains محتملة من اللي اتكشفوا بالفعل (`api.example.com` → `dev-api`, `api-staging`...):
```bash
cat subs/*.txt | anew | sort -u > subs/base_subs.txt

# alterx (ProjectDiscovery)
alterx -l subs/base_subs.txt -o subs/permutations.txt

# gotator (بديل)
gotator -sub subs/base_subs.txt -perm permutation_wordlist.txt -depth 1 -numbers 3 -mindup -adv -md > subs/gotator.txt

# resolve بعد الـ permutation عشان نشوف إيه اللي فعلاً live
cat subs/permutations.txt subs/gotator.txt | anew | puredns resolve - -r resolvers.txt -w subs/permutations_resolved.txt
```

### 1.4 Infrastructure / ASN / Origin IP
```bash
asnmap -a AS17012
echo 66.211.170.0/23 | dnsx -silent -resp-only -ptr
hakrevdns -d $TARGET -R resolvers.txt
```
مصادر يدوية: `bgp.he.net`, `search.censys.io`, `viewdns.info/reverseip`

### 1.5 OSINT إضافي
`securitytrails.com`, `shrewdeye.app`, `netlas.io`, `urlscan.io`, `otx.alienvault.com`, `virustotal.com`, `shodan.io`

### 1.6 Merge & Dedupe (نهاية المرحلة)
```bash
cat subs/*.txt | anew | sort -u | tee subs/AllSubs.txt
wc -l subs/AllSubs.txt
```

**Wordlists:**
```
seclists/Discovery/DNS/dns-Jhaddix.txt
seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
commonspeak2-wordlists/subdomains/subdomains.txt
best-dns-wordlist.txt
```

---

## Phase 2 — DNS Resolution (سكيل كبير)

```bash
# للأعداد الكبيرة جداً massdns أسرع وأخف من puredns
massdns -r resolvers.txt -t A -o S -w resolved/massdns_raw.txt subs/AllSubs.txt

# أو الطريقة العادية
puredns resolve subs/AllSubs.txt -r resolvers.txt -w resolved/ResolvedSubs.txt
```

---

## Phase 3 — Alive Host Detection + Fingerprinting

```bash
cat resolved/ResolvedSubs.txt | httpx -status-code -content-length -web-server -title \
  -follow-redirects -tech-detect -o alive/AliveSubs.txt

cat alive/AliveSubs.txt | httpx -match-code 200 -silent -o alive/200.txt
cat alive/AliveSubs.txt | httpx -filter-code 400 -silent -o alive/400_filtered.txt
```
`404` → روح على wayback + fuzz | `403` → تحقق من الصلاحيات يدوي

**WAF Detection (قبل أي fuzzing عشان تظبط الـ threads):**
```bash
wafw00f -i alive/AliveSubs.txt -o alive/waf_results.txt
```

**TLS/Cert Info (مصدر إضافي غير crt.sh):**
```bash
cat alive/AliveSubs.txt | tlsx -san -cn -silent -o alive/tls_info.txt
```

**Favicon Hash Hunting (لاكتشاف assets تانية لنفس الشركة عبر Shodan/Censys):**
```bash
favfreak -f alive/AliveSubs.txt -o loot/favicon_hashes.txt
```

---

## Phase 4 — URL Discovery

```bash
cat alive/AliveSubs.txt | waybackurls > urls/WB1.txt
waymore -i alive/AliveSubs.txt -mode U -l 1000 -from 2021 -oU urls/WM1.txt
cat alive/AliveSubs.txt | gau --threads 200 > urls/GAU1.txt
cat alive/AliveSubs.txt | hakrawler -subs -u -insecure > urls/HK1.txt
katana -list alive/AliveSubs.txt -jc -kf all -d 5 -headless -fx -aff -fs rdn -f url -silent > urls/KTN1.txt
gospider -S alive/AliveSubs.txt -t 20 -d 3 --js --sitemap --robots -o urls/GS1
paramspider -d $TARGET -o urls/PS1.txt

# Merge نهاية المرحلة
grep -rhoE 'https?://[^ ]+' urls/GS1 2>/dev/null | sort -u | anew urls/AllURLs.txt
cat urls/WB1.txt urls/WM1.txt urls/GAU1.txt urls/KTN1.txt urls/HK1.txt urls/PS1.txt 2>/dev/null \
  | anew | tee -a urls/AllURLs.txt
sort -u urls/AllURLs.txt -o urls/AllURLs.txt
```

---

## Phase 5 — Categorization (استخراج موحّد بدل التكرار)

استخدم loop واحد بدل ما تكرر `cat AllURLs.txt | grep` لكل category على حدة:

```bash
declare -A patterns=(
  [js]="\.js(\?|$)"
  [backend]="\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)"
  [api]="\.(json|xml|graphql|gql)(\?|$)"
  [login]="login|signin|auth|oauth|reset|password"
  [upload]="upload|file|download|image|media"
  [admin]="admin|dashboard|internal|manage"
  [sensitive]="\.(env|bak|config|sql|log)(\?|$)"
  [idor]="[0-9]{2,}"
  [interesting]="admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest="
  [cloud]="aws|s3|bucket|gcp|azure|vault|token|apikey|secret"
  [params]="="
)

for name in "${!patterns[@]}"; do
  grep -Ei "${patterns[$name]}" urls/AllURLs.txt | anew | tee params/$name.txt > /dev/null
done

# Filter live فقط
cat urls/AllURLs.txt | httpx -status-code -content-length -silent > urls/LiveURLs.txt

# Parameter normalization
cat params/params.txt | qsreplace "FUZZ" | anew | tee params/ParamURLs.txt
cat params/params.txt | sed 's/=[^&]*/=/g' | anew | tee params/param_names.txt
```

---

## Phase 6 — JavaScript & Secret Discovery

```bash
cat urls/AllURLs.txt | subjs | sort -u | anew js/js_urls.txt

mkdir -p js/files
while read -r url; do
    fname=$(echo "$url" | sha256sum | awk '{print $1}')
    curl -sL "$url" -o "js/files/$fname.js"
done < js/js_urls.txt

# Regex الأساسي (سريع لكن محدود)
grep -RniE "api[_-]?key|token|secret|password" js/files/ > js/regex_hits.txt

# أدوات مخصصة أدق من الـ grep العادي (بتكشف JWT/private keys/cloud creds بأنماط محددة)
python3 SecretFinder.py -i js/js_urls.txt -o cli >> js/secretfinder_results.txt
mantra -f js/files/ >> js/mantra_results.txt

# Secret scanning شامل
trufflehog filesystem js/files/ --json > loot/trufflehog_js.json
gitleaks detect --source js/files/ --report-format json --report-path loot/gitleaks_js.json
```

---

## Phase 7 — Hidden Parameters

```bash
arjun -i params/backend.txt -oT params/php_parameters.txt
arjun -i urls/AllURLs.txt -oJ params/arjun.json
```

---

## Phase 8 — Directory & Content Fuzzing (موحّدة بدل التكرار)

استخدم أداة واحدة أساسية (feroxbuster) + fallback بدل تكرار نفس الفكرة 5 مرات:

```bash
feroxbuster -u https://$TARGET -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 80 -k -d 3 -e -x php,html,json,js,log,txt,bak,old,zip,tar,gz -o dirs/ferox_results.txt

# لو حابب مصدر تاني للتأكيد فقط (مش تكرار كامل)
dirsearch -u https://$TARGET -e php,asp,aspx,jsp,json,xml,bak,old,zip \
  --exclude-status=404 -o dirs/dirsearch_results.txt

# Fuzzing متقدم بـ ffuf لسيناريوهات خاصة (Auth headers, multi-param)
ffuf -u https://$TARGET/FUZZ -w wordlist.txt -t 200 -mc 200 -recursion -recursion-depth 2 \
  -o dirs/ffuf_results.json
```

**Virtual Host Enumeration:**
```bash
ffuf -u https://$TARGET -w wordlist.txt -H "Host: FUZZ.$TARGET" -mc 200
```

---

## Phase 9 — API Discovery

```bash
kr scan https://api.$TARGET -A=apiroutes-260227:10000 -x 8 -j 15 -v info
kr scan https://api.$TARGET -A=parameters-260227:5000 -x 5 -j 10 -v info
```

---

## Phase 10 — Cloud & Bucket Enumeration (كانت ناقصة)

```bash
s3scanner scan -f params/cloud.txt
cloud_enum -k $TARGET -k "${TARGET%%.*}" -l cloud/cloud_enum_results.txt
```

---

## Phase 11 — CORS Misconfiguration (كانت ناقصة)

```bash
python3 Corsy.py -i alive/AliveSubs.txt -o loot/corsy_results.json
```

---

## Phase 12 — Vulnerability Scanning

```bash
nuclei -l subs/AllSubs.txt -t http/exposures -o vulns/exposures.txt
nuclei -l alive/AliveSubs.txt -t cves/ -severity critical,high -o vulns/cves.txt
nuclei -l alive/AliveSubs.txt -t misconfiguration/ -o vulns/misconfig.txt
```

---

## Phase 13 — Port Scanning

```bash
naabu -list alive/AliveSubs.txt -p - -rate 2000 -o ports/ports.txt
nmap -iL alive/AliveSubs.txt -T4 -Pn -oN ports/nmap_results.txt
```

---

## Phase 14 — GitHub / Google Dorks (Manual Review)

```text
site:*.target.com intext:"docs.google.com/spreadsheets"
"target.com" api_key
"target.com" secret
"target.com" token
```
```bash
trufflehog git https://github.com/example/repo --results=verified
```

---

## Wordlists Reference
```
seclists/Discovery/DNS/dns-Jhaddix.txt
seclists/Discovery/Web-Content/raft-large-directories.txt
seclists/Discovery/Web-Content/raft-medium-directories.txt
seclists/Discovery/Web-Content/burp-parameter-names.txt
best-dns-wordlist.txt
```

---

## أهم الإضافات اللي اتحطت (ملخص سريع)
1. **Wildcard detection** قبل أي bruteforce
2. **Subdomain permutation** (alterx/gotator) — أكبر فجوة كانت موجودة
3. **Massdns** للـ resolving بسكيل كبير
4. **WAF detection** قبل الـ fuzzing لضبط الـ threads
5. **tlsx** لمصدر تاني غير crt.sh
6. **Favicon hashing** لاكتشاف assets تانية
7. **S3/Cloud bucket enumeration** فعلي (مش grep بس)
8. **CORS scanning** (Corsy)
9. **SecretFinder/Mantra** بدل الاعتماد الكلي على regex بسيط
10. **Categorization بـ loop موحد** بدل تكرار نفس الأمر لكل نوع ملف
11. **معايير موحدة** للـ threads/rate/resume عبر الأدوات
