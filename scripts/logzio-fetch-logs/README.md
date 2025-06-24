## 📦 Logz.io Scroll API Fetcher

This tool fetches large volumes of logs from [Logz.io](https://logz.io/) using the Scroll API and saves them in either **JSON** or **CSV** format. It supports pagination, filtering, `.env` token loading, and advanced query input.

### ✅ Features

* ✅ Fetch more than 10,000 logs (up to hundreds of thousands)
* ✅ Supports `--query`, `--limit`, `--format`, and `--output`
* ✅ Automatically loads your API token from `.env` or CLI
* ✅ Outputs structured logs in JSON or tabular CSV
* ✅ Uses `config.json` to simplify common payload settings (optional)

---

## 📥 Installation

1. Clone this repo or copy the script:

   ```bash
   git clone https://github.com/your-org/logzio-scroll-fetcher.git
   cd logzio-scroll-fetcher
   ```

2. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your token:

   ```bash
   echo 'LOGZIO_API_TOKEN=your-api-token' > .env
   ```

---

## 🧪 Usage

```bash
python3 logzio_fetch_logs.py --query "<lucene-query>" --limit 50000 --format json
```

### Example

```bash
python3 logzio_fetch_logs.py \
  --query "*" \
  --limit 100000 \
  --format csv \
  --output logs-output.csv
```

### Optional Flags

| Flag       | Description                                            |
| ---------- | ------------------------------------------------------ |
| `--query`  | Required. Lucene query to run.                         |
| `--limit`  | Number of logs to fetch. Default: 10,000.              |
| `--format` | Output format: `json` or `csv`.                        |
| `--output` | Output filename. Default: `logs-<timestamp>.json/csv`. |
| `--token`  | API token (optional if in `.env`)                      |

---

## ⚙️ Configuration File (Optional)

You can add a `config.json` to define reusable query blocks or settings.

Example:

```json
{
    "csv_fields": [
        "@timestamp",
        "message",
        "host_name",
        "type",
        "k8s_container_name",
        "k8s_namespace_name",
        "log_level",
        "k8s_pod_name"
    ],
    "json_fields": [
        "@timestamp",
        "message",
        "host_name",
        "type",
        "k8s_container_name",
        "k8s_namespace_name"
    ],
    "default_query": "INFO",
    "time_range": {
        "gte": "now-60d",
        "lte": "now"
    }
}
```

The script will automatically load this if found.

---

## 📁 Output

* JSON: Pretty-printed array of logs with full fields
* CSV: Flattened `_source` fields into headers and rows

---

## 🛡 Requirements

* Python 3.7+
* `requests`
* `python-dotenv`

---

## 🧯 Troubleshooting

* Make sure your token is valid and matches the target Logz.io account
* Query `"*"` may not match if there's no data within the last 60 days
* Scroll session expires if idle for too long – the script handles this

---

## 👨‍💻 Maintainers

* Built by and for engineers who need **bulk log extraction** from Logz.io without dashboard constraints.
