# NesTrace
A Python tool that queries Nessus via its REST API and identifies all scans in which specified hosts (domain or IP) were analyzed.

The script logs into Nessus, enumerates all scans, inspects their hosts, and generates a CSV report showing where each asset appears.

# Installation
```bash
pip install -r requirements.txt
```

# Run the script
Usage
```bash
python3 nestrace.py -n https://nessus.company.local:8834 -i assets.csv -o results.csv
```

| **Argument** | **Description** | **Required** |
|------------- | --------------- | ------------ |
| `-n`	| Nessus base URL	 | ✅ |
| `-i`	| Input CSV file	 | ✅ |
| `-o`	| Output CSV file (default: results.csv)	 | ❌ |

After launching the script, you will be prompted for:

```bash
Username:
Password:
```

The script authenticates via:
```bash
POST /session
```

and uses the returned API token for further requests.

![](.img/run_example.png)

## Input CSV file
```bash
TEST-ASSET01.acme.local,10.0.0.1
TEST-ASSET02.acme.com,10.0.0.2
TEST-ASSET03,10.0.0.3
10.0.0.1,TEST-ASSET01.acme.local
10.0.0.2,TEST-ASSET02.acme.com
10.0.0.3,TEST-ASSET03
```

## Output CSV file
```bash
TEST-ASSET02.acme.com,10.0.0.2,Weekly Scan,admin,https://nessus.local/#/scans/reports/12/hosts/3/vulnerabilities
```