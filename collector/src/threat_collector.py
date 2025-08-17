import sys
import time
import bz2
import csv
import logging
import os
import requests
import zipfile
import datetime as dt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Generator, List
from contextlib import contextmanager
from pathlib import Path
from dataclasses import dataclass
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import hashlib
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from io import BytesIO
from logging.handlers import RotatingFileHandler
import configparser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets, tempfile, requests, json, os

# Disable SSL warnings for development - remove in production
disable_warnings(InsecureRequestWarning)

load_dotenv()



@dataclass
class ThreatData:
    """Data class for threat intelligence records."""
    url: str
    threat: str
    source: str
    date_added: str


@dataclass
class Config:
    """Configuration data class."""
    es_host: str
    es_port: int
    es_password: str
    es_scheme: str
    es_user: str = 'elastic'
    eti_host: str = 'ucs.eunomatix.com'
    eti_port: str = '8050'
    authcode: str = ''
    proxy_mode: bool = False
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    eti_index_ttl: int = 90


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


class NetworkError(Exception):
    """Raised when network operations fail."""
    pass

class ETIDataError(Exception):
    """Raised when ETI data processing fails."""
    pass



class ThreatCollectorService:
    """Main service class for threat intelligence collection."""

    # Constants
    MAX_RETRIES = 3
    RETRY_DELAY = 30
    REQUEST_TIMEOUT = (20, 100)  # (connect, read) timeouts
    INDEX_NAME_PREFIX = "threat_index"
    PHISHTANK_URL = 'https://data.phishtank.com/data/online-valid.csv.bz2'
    URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/csv/'
    OUTPUT_FILE = 'latest_data.csv'
    FIELDNAMES = ['url', 'threat', 'source', 'date_added']
    BATCH_SIZE = 5000
    AES_KEY = b"cmjeWPxhgNQ2rp0RImhk65G4K0yOj7cB"  # must be 32 bytes

    def __init__(self, config_path: str = "/app/watchdog.conf"): 
        self.logger = self._setup_logging()
        self.config_path = Path(config_path)
        self.config = self._load_and_validate_config()
        self.es_client = self._create_elasticsearch_client()
        self.session = self._create_http_session()
        self.three_months_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        self.api_url = f"https://{self.config.eti_host}:{self.config.eti_port}/pull-eti"

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with rotation and console output."""
        log_dir = Path("/app/logs") 
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "threat_collector.log"

        # Create formatters
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )

        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)

        # Configure logger
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        # Prevent duplicate logs
        logger.propagate = False

        return logger


    def _decrypt_eti_data(self, enc_bytes: bytes) -> list[dict]:
        """Decrypt AES-256-CBC encrypted ETI data and return parsed JSONL list."""
        iv = enc_bytes[:16]
        ciphertext = enc_bytes[16:]

        cipher = Cipher(algorithms.AES(self.AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Parse JSONL
        eti_data = []
        for line in plaintext.decode("utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    eti_data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self.logger.error(f"Error parsing JSON line: {e}")
                    continue
        return eti_data


    def _load_and_validate_config(self) -> Config:
        """Load and validate configuration from environment and config file."""
        try:
            # Load from environment
            es_host = os.getenv('ES_HOST')
            es_port = os.getenv('ES_PORT')
            es_password = os.getenv('ES_PASSWORD')
            es_scheme = os.getenv('ES_SCHEME')

            if not all([es_host, es_port, es_password, es_scheme]):
                raise ConfigurationError("Missing required environment variables")

            # Load config file
            config_parser = configparser.ConfigParser()
            if self.config_path.exists():
                config_parser.read(self.config_path)
            else:
                self.logger.warning(f"Config file {self.config_path} not found")

            # Create config object
            config = Config(
                es_host=es_host,
                es_port=int(es_port),
                es_password=es_password,
                es_scheme=es_scheme,
                eti_host=config_parser.get('eti', 'eti_host', fallback='ucs.eunomatix.com'),
                eti_port=config_parser.get('eti', 'eti_port', fallback='8050'),
                eti_index_ttl=config_parser.getint('eti', 'eti_index_ttl', fallback=90),
                authcode=config_parser.get('default', 'authcode', fallback=''),
                proxy_mode=config_parser.getboolean('proxy', 'proxy_mode', fallback=False),
                http_proxy=config_parser.get('proxy', 'http_proxy', fallback='').strip() or None,
                https_proxy=config_parser.get('proxy', 'https_proxy', fallback='').strip() or None
            )

            # Validate proxy configuration
            if config.proxy_mode and not (config.http_proxy or config.https_proxy):
                raise ConfigurationError("Proxy mode enabled but no valid proxy URLs found")

            return config

        except Exception as e:
            raise ConfigurationError(f"Configuration error: {e}")

    def _create_elasticsearch_client(self) -> Elasticsearch:
        """Create and configure Elasticsearch client."""
        try:
            return Elasticsearch(
                [{'host': self.config.es_host, 'port': self.config.es_port, 'scheme': self.config.es_scheme}],
                basic_auth=(self.config.es_user, self.config.es_password),
                verify_certs=False,  # Set to True in production with proper certs
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                request_timeout=60,
                max_retries=5,
                retry_on_timeout=True,
                ca_certs='/certs/ca.crt',
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
        except Exception as e:
            raise ConfigurationError(f"Failed to create Elasticsearch client: {e}")

    def _create_http_session(self) -> requests.Session:
        """Create HTTP session with proper configuration."""
        session = requests.Session()

        # Configure proxies
        if self.config.proxy_mode:
            proxies = {}
            if self.config.http_proxy:
                proxies['http'] = self.config.http_proxy
            if self.config.https_proxy:
                proxies['https'] = self.config.https_proxy
            session.proxies.update(proxies)
            self.logger.info(f"Proxies configured: {proxies}")

        # Configure adapter with connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0  # We handle retries manually
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Set default headers
        session.headers.update({
            'User-Agent': 'ThreatCollector/1.0',
            'Accept': '*/*',
            'Connection': 'close'  # Ensure connections are closed
        })

        return session

    @contextmanager
    def _safe_request(self, url: str, params: Dict[str, Any]):
        """Context manager for safe HTTP requests with proper cleanup."""
        response = None
        try:
            response = self.session.get(
                url,
                params=params,
                verify=False,  # Set to True in production
                timeout=self.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            yield response
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            raise NetworkError(f"Request failed: {e}")
        finally:
            if response:
                response.close()

    def _download_with_retry(self, url: str) -> Optional[bytes]:
        """Download data with retry logic and proper cleanup."""
        for attempt in range(self.MAX_RETRIES):
            try:
                with self._safe_request(url) as response:
                    self.logger.info(f"Successfully downloaded from {url}")
                    return response.content
            except NetworkError as e:
                self.logger.warning(f"Download attempt {attempt + 1} failed for {url}: {e}")
                if attempt < self.MAX_RETRIES - 1:
                    self.logger.info(f"Retrying in {self.RETRY_DELAY} seconds...")
                    time.sleep(self.RETRY_DELAY)

        self.logger.error(f"All download attempts failed for {url}")
        return None

    def _convert_to_standard_date(self, date_string: str) -> str:
        """Convert various date formats to standard format."""
        try:
            return datetime.fromisoformat(
                date_string.replace("Z", "+00:00")
            ).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            self.logger.error(f"Error parsing date string: {date_string}")
            return ''

    def _is_recent_date(self, date_string: str) -> bool:
        """Check if date is within the last 3 months."""
        try:
            date_object = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
            threshold = datetime.strptime(self.three_months_ago, '%Y-%m-%d %H:%M:%S')
            return date_object >= threshold
        except ValueError:
            self.logger.error(f"Error comparing date: {date_string}")
            return False


    def _download_and_process_data(self) -> None:
        """Download and process threat intelligence data."""
        output_path = Path(self.OUTPUT_FILE)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writeheader()

                # Process both data sources
                self._process_phishtank_data(writer)
                self._process_urlhaus_data(writer)

        except Exception as e:
            self.logger.error(f"Error in data processing pipeline: {e}")
            raise

    def _rollover_index(self) -> None:
        """Perform index rollover."""
        try:
            alias = self.INDEX_NAME_PREFIX
            response = self.es_client.indices.rollover(alias=alias, body={})

            if response.get("acknowledged"):
                self.logger.info(f"Rollover successful for alias: {alias}")
                self.logger.info(f"New index created: {response.get('new_index')}")
            else:
                self.logger.warning(f"Rollover response for alias {alias}: {response}")

        except Exception as e:
            self.logger.error(f"Error during rollover for alias {alias}: {e}")
            raise

    def _get_current_index(self) -> str:
        """Get the current active index."""
        try:
            alias = self.INDEX_NAME_PREFIX
            response = self.es_client.indices.get_alias(name=alias)
            return list(response.keys())[0]
        except Exception as e:
            self.logger.error(f"Error getting current index: {e}")
            raise

    def _is_index_empty(self, index_name: str) -> bool:
        """Check if index is empty."""
        try:
            doc_count = self.es_client.count(index=index_name)['count']
            self.logger.info(f"Index {index_name} contains {doc_count} documents")
            return doc_count == 0
        except Exception as e:
            self.logger.error(f"Error checking document count in index {index_name}: {e}")
            return False
    def _generate_bulk_actions(self, eti_data: List[Dict[str, Any]], index_name: str) -> Generator[Dict[str, Any], None, None]:
        """Generate bulk actions for Elasticsearch."""
        try:
            for item in eti_data:
                yield {
                    "_op_type": "index",
                    "_index": index_name,
                    "_source": {
                        "url": item.get("url"),
                        "threat": item.get("threat"),
                        "source": item.get("source"),
                        "date_added": item.get("date_added")
                    }
                }
        except Exception as e:
            self.logger.error(f"Error generating bulk actions: {e}")
            raise



    def _bulk_insert_to_elasticsearch(self, eti_data: List[Dict[str, Any]]) -> bool:
        """Insert ETI data to Elasticsearch using bulk operations."""
        
        if not eti_data:
            self.logger.info("No ETI data to insert")
            return True

        try:
            self.logger.info(f"Inserting {len(eti_data)} records into Elasticsearch")
            index_name = self._get_current_index()
            self.logger.info(f"Inserting data into index: {index_name}")

            
            actions = list(self._generate_bulk_actions(eti_data, index_name))
            if not actions:
                self.logger.warning("No valid actions generated for bulk insert")
                return False

            success, errors = bulk(
                self.es_client,
                actions,
                chunk_size=self.BATCH_SIZE,
                raise_on_error=False
            )

            self.logger.info(f"Bulk insert completed: {success} successful, {len(errors)} errors")
            
            if errors:
                self.logger.error(f"Bulk insert errors (first 5): {errors[:5]}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error during bulk insert: {e}")
            return False

    def _delete_old_indices(self) -> None:
        """Delete indices older than configured TTL."""
        try:
            threshold_date = datetime.now() - timedelta(days=self.config.eti_index_ttl)
            indices = self.es_client.indices.get(index=f"{self.INDEX_NAME_PREFIX}-*").keys()

            self.logger.info(f"Checking indices for deletion (threshold: {threshold_date.strftime('%Y-%m-%d')})")

            deleted_count = 0
            for index in indices:
                try:
                    index_info = self.es_client.indices.get(index=index)
                    creation_date_ms = index_info[index]["settings"]["index"].get("creation_date")

                    if not creation_date_ms:
                        self.logger.warning(f"Skipping {index}: No creation_date found")
                        continue

                    creation_date = datetime.utcfromtimestamp(int(creation_date_ms) / 1000)

                    if creation_date < threshold_date:
                        self.es_client.indices.delete(index=index)
                        self.logger.info(f"Deleted old index: {index} (created: {creation_date.strftime('%Y-%m-%d')})")
                        deleted_count += 1

                except Exception as e:
                    self.logger.warning(f"Error processing index {index}: {e}")

            self.logger.info(f"Deleted {deleted_count} old indices")

        except Exception as e:
            self.logger.error(f"Error deleting old indices: {e}")

        # Generate a hash using license_key and authcode
    def _generate_auth_hash(self, authcode: str) -> str:
        """Generate authentication hash using SHA3-512."""
        try:
            return hashlib.sha3_512(authcode.encode('utf-8')).hexdigest()
        except Exception as e:
            self.logger.error(f"Error generating auth hash: {e}")
            raise ETIDataError(f"Failed to generate auth hash: {e}")
        
    def _download_eti_data_with_retry(self) -> Optional[bytes]:
        """Download encrypted ETI data with retry logic."""
        auth_hash = self._generate_auth_hash(self.config.authcode)
        params = {"auth_hash": auth_hash}

        for attempt in range(self.MAX_RETRIES):
            try:
                with self._safe_request(self.api_url, params) as response:
                    self.logger.info(f"Successfully downloaded encrypted ETI data from {self.api_url}")
                    return response.content
            except NetworkError as e:
                self.logger.warning(f"Download attempt {attempt + 1} failed: {e}")
                if attempt < self.MAX_RETRIES - 1:
                    self.logger.info(f"Retrying in {self.RETRY_DELAY} seconds...")
                    time.sleep(self.RETRY_DELAY)

        self.logger.error("All download attempts failed for ETI API")
        return None


    def fetch_and_store_eti_data(self) -> None:
        """Main method to fetch, decrypt, and store ETI data."""
        try:
            self.logger.info("Starting ETI data collection")

            # Download encrypted data
            enc_content = self._download_eti_data_with_retry()
            if not enc_content:
                self.logger.warning("Failed to download ETI data")
                return

            # Decrypt and parse JSONL
            eti_data = self._decrypt_eti_data(enc_content)
            if not eti_data:
                self.logger.info("No new ETI data to process")
                return

            # Insert to Elasticsearch
            if self._bulk_insert_to_elasticsearch(eti_data):
                self.logger.info("ETI data collection completed successfully.")
            else:
                self.logger.error("Failed to insert ETI data.")

            # Cleanup output file
            output_path = Path(self.OUTPUT_FILE)
            if output_path.exists():
                output_path.unlink()

        except Exception as e:
            self.logger.error(f"ETI data collection failed: {e}", exc_info=True)
            raise


    def run_pipeline(self) -> None:
        """
        Main pipeline steps: rollover, check index emptiness, delete old indeces, download, insert to ES.
        """
        """Execute the complete data collection pipeline."""
        try:
            self.logger.info("Starting threat intelligence collection pipeline")

            # Index management
            self._rollover_index()
            active_index = self._get_current_index()
            self._delete_old_indices()

            # Check if processing is needed
            if not self._is_index_empty(active_index):
                self.logger.info("Active index is not empty. Skipping data processing")
                return
            self.fetch_and_store_eti_data()       
            # Cleanup
            output_path = Path(self.OUTPUT_FILE)
            if output_path.exists():
                output_path.unlink()

            self.logger.info("Pipeline execution completed successfully")

        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}")
            raise


    def start_scheduler(self) -> None:
        """Start the scheduler to run pipeline daily at midnight."""
        self.logger.info("Starting threat collector scheduler")

        while True:
            try:
                now = dt.datetime.now()
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0)
                if next_run <= now:
                    next_run += dt.timedelta(days=1)

                seconds_until_next_run = (next_run - now).total_seconds()
                self.logger.info(f"Next run scheduled in {seconds_until_next_run:.0f} seconds")

                time.sleep(seconds_until_next_run)
                self.run_pipeline()

            except KeyboardInterrupt:
                self.logger.info("Scheduler stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Pipeline execution failed: {e}")
                # Continue running despite errors

    def cleanup(self) -> None:
        """Cleanup resources."""
        try:
            if hasattr(self, 'session'):
                self.session.close()
            self.logger.info("Service cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


def main():
    """Main entry point."""
    init_flag_path = Path('/app/init/initialized')

    try:
        with ThreatCollectorService() as service:
            if not init_flag_path.exists():
                # Initial run
                service.run_pipeline()
                sys.exit(0)
            else:
                # Start scheduler
                service.start_scheduler()

    except KeyboardInterrupt:
        print("Service stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Service failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
