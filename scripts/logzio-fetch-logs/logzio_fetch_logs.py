import requests
import json
import csv
import time
import argparse
import os
from datetime import datetime
from dotenv import load_dotenv

# Load .env if exists
load_dotenv()

# Helper function to sanitize and validate file paths
def sanitize_file_path(file_path, base_directory):
    """
    Validates and sanitizes a file path to prevent path traversal attacks.
    Ensures the file path is within the allowed base directory.

    Args:
        file_path (str): The path to the file.
        base_directory (str): The base directory where files are allowed.

    Returns:
        str: The sanitized and validated absolute path to the file.

    Raises:
        RuntimeError: If the file path is invalid or attempts to escape the base directory.
    """
    # Normalize the file path to prevent path traversal
    normalized_file_path = os.path.normpath(file_path)

    # Ensure the resolved path is within the base directory
    resolved_path = os.path.abspath(os.path.join(base_directory, normalized_file_path))
    if not os.path.commonpath([base_directory, resolved_path]) == base_directory:
        raise RuntimeError(f"Access to the file '{file_path}' is not allowed.")

    return resolved_path

# Load configuration
def load_config(config_file="config.json"):
    BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
    config_path = sanitize_file_path(config_file, BASE_DIRECTORY)

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Configuration file '{config_file}' not found.")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Error parsing configuration file: {e}")

# Constants
SEARCH_URL = "https://api.logz.io/v1/scroll"
HEADERS = lambda token: {
    "Content-Type": "application/json",
    "X-API-TOKEN": token
}

# Function to get token from CLI or .env
def get_api_token(cli_token=None):
    token = cli_token or os.getenv("LOGZIO_API_TOKEN")
    if not token:
        raise ValueError("API token must be provided via --token or LOGZIO_API_TOKEN in .env")
    return token

def start_scroll(token, payload):
    try:
        resp = requests.post(SEARCH_URL, headers=HEADERS(token), json=payload, timeout=3600)
        print(f"Response status: {resp.status_code}")
        print(f"Response headers: {resp.headers}")
        print(f"Response body: {resp.text}")
        if "application/json" not in resp.headers.get("Content-Type", ""):
            print("❌ Non-JSON response received:")
            print(resp.text)
            raise RuntimeError(f"Unexpected response format: {resp.text}")
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Error initiating scroll: {e}")

def continue_scroll(token, scroll_id):
    try:
        resp = requests.post(SEARCH_URL, headers=HEADERS(token), json={"scroll_id": scroll_id}, timeout=3600)
        print(f"Response status: {resp.status_code}")
        print(f"Response headers: {resp.headers}")
        print(f"Response body: {resp.text}")
        if "application/json" not in resp.headers.get("Content-Type", ""):
            print("❌ Non-JSON response received:")
            print(resp.text)
            raise RuntimeError(f"Unexpected response format: {resp.text}")
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Error during scroll pagination: {e}")

# Save logs to JSON
def save_to_json(logs, output_file, json_fields):
    BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
    output_file_path = sanitize_file_path(output_file, BASE_DIRECTORY)

    try:
        filtered_logs = []
        for entry in logs:
            source = entry.get("_source", {})
            filtered_entry = {}
            for field in json_fields:
                value = source.get(field, "")
                # Convert @timestamp from epoch to ISO 8601 if applicable
                if field == "@timestamp" and isinstance(value, (int, float)):
                    value = datetime.utcfromtimestamp(value / 1000).isoformat() + "Z"
                filtered_entry[field] = value
            filtered_logs.append(filtered_entry)
        with open(output_file_path, "w") as f:
            json.dump(filtered_logs, f, indent=2)
        print(f"✅ Saved {len(filtered_logs)} logs to {output_file_path}")
    except IOError as e:
        raise RuntimeError(f"Error writing JSON file: {e}")

# Save logs to CSV with filtered fields
def save_to_csv(logs, output_file, csv_fields):
    BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
    output_file_path = sanitize_file_path(output_file, BASE_DIRECTORY)

    if not logs:
        print("⚠️ No logs to save to CSV.")
        return
    try:
        with open(output_file_path, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(csv_fields)  # Write header row
            for entry in logs:
                source = entry.get("_source", {})
                row = []
                for field in csv_fields:
                    value = source.get(field, "")
                    # Convert @timestamp from epoch to ISO 8601 if applicable
                    if field == "@timestamp" and isinstance(value, (int, float)):
                        value = datetime.utcfromtimestamp(value / 1000).isoformat() + "Z"
                    row.append(value)
                writer.writerow(row)
        print(f"✅ Saved {len(logs)} logs to {output_file_path}")
    except IOError as e:
        raise RuntimeError(f"Error writing CSV file: {e}")

# Fetch logs using scroll loop
def fetch_logs(token, query_string, limit, time_range):
    all_logs = []
    payload = {
        "size": min(limit, 1000),  # Limit the size to 1000 per API constraints
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": query_string,
                            "analyze_wildcard": True,
                            "time_zone": "UTC"
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_range["gte"],
                                "lte": time_range["lte"]
                            }
                        }
                    }
                ]
            }
        }
    }

    print("🔍 Initiating scroll...")
    initial = start_scroll(token, payload)
    scroll_id = initial.get("scrollId")
    hits_raw = initial.get("hits", {})

    # Parse hits_raw if it's a JSON string
    if isinstance(hits_raw, str):
        try:
            hits_raw = json.loads(hits_raw)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Error parsing 'hits' field: {e}")

    hits = hits_raw.get("hits", [])
    total = hits_raw.get("total", 0)

    print(f"✅ Scroll initiated. Total logs: {total}")

    # Append initial hits to all_logs
    all_logs.extend(hits)

    # Continue scrolling until all logs are fetched or limit is reached
    while len(all_logs) < limit and len(hits) > 0:
        print(f"🔄 Fetching next batch of logs... ({len(all_logs)}/{limit})")
        response = continue_scroll(token, scroll_id)
        scroll_id = response.get("scrollId")
        hits_raw = response.get("hits", {})

        # Parse hits_raw if it's a JSON string
        if isinstance(hits_raw, str):
            try:
                hits_raw = json.loads(hits_raw)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Error parsing 'hits' field: {e}")

        hits = hits_raw.get("hits", [])
        all_logs.extend(hits)

    print(f"✅ Fetched {len(all_logs)} logs.")
    return all_logs

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch logs from Logz.io using Scroll API")
    parser.add_argument("--token", help="Your Logz.io API token (or set LOGZIO_API_TOKEN in .env)")
    parser.add_argument("--query", help="Lucene query string (default from config)")
    parser.add_argument("--config", default="config.json", help="Path to configuration file (default: config.json)")
    parser.add_argument("--limit", type=int, default=10000, help="Number of logs to fetch (default: 10000)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    parser.add_argument("--output", help="Output file name (default: logs-<timestamp>.<ext>)")

    args = parser.parse_args()

    try:
        BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
        config = load_config(args.config)
        token = get_api_token(args.token)
        query_string = args.query or config.get("default_query", "INFO")
        time_range = config.get("time_range", {"gte": "now-60d", "lte": "now"})
        logs = fetch_logs(token, query_string, args.limit, time_range)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = args.output or f"logs-{ts}.{args.format}"
        if args.format == "json":
            save_to_json(logs, output_file, config["json_fields"])
        else:
            save_to_csv(logs, output_file, config["csv_fields"])
    except Exception as ex:
        print(f"❌ Error: {ex}")
