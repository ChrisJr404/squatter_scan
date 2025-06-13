import argparse, asyncio, aiohttp, socket, ssl, tldextract, whois, csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import time
from pathlib import Path

# ✅ Offline-safe tldextract
tldextract.extract = tldextract.TLDExtract(
    cache_dir=False,
    suffix_list_urls=[],
)

console = Console()

CLOUD_LISTS = [
    "https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt",
    "https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt",
    "https://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt",
    "https://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt",
    "https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt",
]

def generate_variants(domain):
    parts = tldextract.extract(domain)
    base, suffix = parts.domain, parts.suffix
    variants = set()

    # TLD swaps
    common_tlds = ['com', 'net', 'org', 'co', 'io']
    for tld in common_tlds:
        if tld != suffix:
            variants.add(f"{base}.{tld}")

    # Typos
    variants.update({
        f"{base}1.{suffix}",
        f"{base}0.{suffix}",
        f"{base[:-1]}.{suffix}",
        f"{base}{base[-1]}.{suffix}",
        f"{base}-{suffix}.{suffix}",
        f"{base}{suffix}.com"
    })

    # Vowel swaps
    vowels = 'aeiou'
    for i, char in enumerate(base):
        if char in vowels:
            for v in vowels:
                if v != char:
                    variants.add(base[:i] + v + base[i+1:] + "." + suffix)

    # Homoglyphs
    glyphs = {
        'o': ['0'], 'l': ['1', 'I'],
        'i': ['1', 'l'], 'e': ['3'],
        'a': ['@'], 's': ['5']
    }
    for i, c in enumerate(base):
        if c in glyphs:
            for rep in glyphs[c]:
                variants.add(base[:i] + rep + base[i+1:] + "." + suffix)

    return list(variants)

async def resolve(domain):
    try: return socket.gethostbyname(domain)
    except: return None

async def check_ip_against_cloud_lists(ip_to_check):
    async with aiohttp.ClientSession() as session:
        for url in CLOUD_LISTS:
            try:
                async with session.get(url, timeout=30) as resp:
                    async for line in resp.content:
                        if line.decode().strip() == ip_to_check:
                            return "Yes"
            except Exception as e:
                console.print(f"[red]Cloud check failed for {url}:[/red] {e}")
    return "No"

def get_creation_year(domain, retries=2, delay=3):
    for attempt in range(retries):
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list): created = created[0]
            if created:
                return created.strftime("%Y-%m-%d")
        except Exception as e:
            console.print(f"[yellow]WHOIS error for {domain} (attempt {attempt+1}):[/yellow] {e}")
            time.sleep(delay)
    return "Unknown"

def is_newly_registered(date_str, days=30):
    if date_str == "Unknown":
        return "Unknown"
    try:
        created_date = datetime.strptime(date_str, "%Y-%m-%d")
        return "Yes" if (datetime.now() - created_date).days < days else "No"
    except:
        return "Unknown"

async def analyze_domain(session, domain, cloud_check=True):
    ip = await resolve(domain)
    if not ip:
        return domain, False, None, "N/A", False, "N/A", "Unknown"

    cloud = await check_ip_against_cloud_lists(ip) if cloud_check else "Skipped"

    sslok = False
    try:
        async with session.get(f"https://{domain}", ssl=False, timeout=5) as resp:
            sslok = resp.status in [200, 301, 302]
    except:
        pass

    created = get_creation_year(domain)
    new = is_newly_registered(created)

    return domain, True, ip, cloud, sslok, created, new

async def main(domain_file, cloud_check, export_path=None):
    with open(domain_file) as f:
        domains = [d.strip() for d in f if d.strip()]

    all_variants = []
    for domain in domains:
        all_variants.extend(generate_variants(domain))

    table = Table(title="Squatter Detection Results")
    for col in ["Domain", "Registered", "IP", "Cloud", "SSL", "Created", "New?"]:
        table.add_column(col)

    results = []

    async with aiohttp.ClientSession() as session:
        with Progress() as progress:
            task = progress.add_task("Checking...", total=len(all_variants))
            for variant in all_variants:
                d, r, ip, cloud, sslok, created, new = await analyze_domain(session, variant, cloud_check)
                if r:
                    table.add_row(d, "Yes", ip or "-", cloud, "Yes" if sslok else "No", created, new)
                    results.append([d, ip or "-", cloud, "Yes" if sslok else "No", created, new])
                progress.advance(task)

    console.print(table)

    if export_path:
        output = Path(export_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "IP", "Cloud", "SSL", "Created", "New?"])
            writer.writerows(results)
        console.print(f"[green]CSV export saved to:[/green] {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", required=True, help="Path to input domain list")
    parser.add_argument("--no-cloud-check", action="store_true", help="Disable cloud IP checking")
    parser.add_argument("--export", help="Optional CSV export path")
    args = parser.parse_args()
    asyncio.run(main(args.domains, not args.no_cloud_check, args.export))
