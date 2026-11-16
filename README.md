# azure-nsg-audit

azure-nsg-audit reads the JSON from `az network nsg list` or `az network nsg show` (or an ARM export) and reports security rules that expose a workload: SSH, RDP, WinRM or SMB open to the internet, database ports open to the internet, any port from any source, very wide port ranges, rules with protocol `*`, rules without a description and unrestricted outbound allows. Findings name the NSG and the rule.

**Live demo:** https://jvch0512.github.io/azure-nsg-audit/ (Synthetic data.)

Visual Basic .NET on .NET 8, no packages. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
bin/azure-nsg-audit examples
bin/azure-nsg-audit ./exports --tsv
bin/azure-nsg-audit ./exports --fail-on high       # exit 1 on any high finding
```

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input. Output is human text by default and TSV with `--tsv` (`# N files, M findings`, then `SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE`).

| Rule | Severity | What it catches |
|---|---|---|
| NSG001 | critical | an inbound Allow from the internet to 22, 23, 445, 3389, 5985 or 5986 |
| NSG002 | high | an inbound Allow from the internet to a database or cache port: 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017 |
| NSG003 | high | an inbound Allow from the internet to every port (`*`) |
| NSG004 | medium | an inbound Allow from the internet to a range of more than 100 ports |
| NSG005 | medium | an inbound Allow from the internet with protocol `*` |
| NSG006 | low | an Allow rule with no description |
| NSG007 | medium | a custom outbound Allow to the internet on every port |
| NSG000 | info | the file is not valid JSON or has no network security groups |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It reads the rules as exported. Application security groups, service tags other than `Internet`, and Azure Firewall are not resolved.
- Sources counted as the internet: `*`, `Internet`, `Any`, `0.0.0.0/0`, `0.0.0.0` and `::/0`. A service tag such as `AzureLoadBalancer` is not.
- Default rules (priority 65000 and above) are ignored.
- Flow logs and effective routes are not part of an NSG export.

## Where it fits

Cloud security reviews of Azure subscriptions, and quick checks of exported NSGs before a customer call.

## Tests

```bash
make test    # A VB.NET test program: every rule on good and bad NSGs, port range parsing, both export shapes, hostile JSON, fuzzing and CLI exit codes
```

MIT.
