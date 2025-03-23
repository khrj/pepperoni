import redis
import json
import hashlib
from typing import Optional, Dict, Any


class RedisCache:
    """
    Redis-based caching system for PCAP analysis results.

    This class handles:
    1. Storing analysis results with file checksums as keys
    2. Retrieving cached analysis results
    3. Checking if analysis results for a file already exist
    """

    def __init__(
        self,
        host="localhost",
        port=6379,
        db=0,
        password=None,
        expiration_time=86400,
        prefix="pcap_analysis:",
        file_prefix="file_id:",
    ):
        """
        Initialize Redis connection.

        Args:
            host (str): Redis host
            port (int): Redis port
            db (int): Redis database number
            password (str): Redis password (if required)
            expiration_time (int): Time in seconds before cache entries expire (default: 24 hours)
            prefix (str): Prefix for all Redis keys
        """
        self.redis_client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=False,  # Keep as bytes for binary data
        )
        self.expiration_time = expiration_time
        self.prefix = prefix
        self.file_prefix = file_prefix

    def _generate_key(self, checksum: str) -> str:
        """Generate a Redis key based on file checksum."""
        return f"{self.prefix}{checksum}"

    def _generate_file_key(self, file_id: str) -> str:
        return f"{self.file_prefix}{file_id}"

    def store_analysis(
        self, checksum: str, file_id: str, analysis_data: Dict[str, Any]
    ) -> bool:
        """
        Store analysis results in Redis with file checksum as key.

        Args:
            checksum (str): File checksum
            file_id (str): Unique file identifier
            analysis_data (dict): Analysis results

        Returns:
            bool: True if storage was successful
        """
        try:
            # Create a dictionary with file_id and analysis results
            cache_data = {"analysis_results": analysis_data}

            # Convert to JSON string and store in Redis
            cache_data_json = json.dumps(cache_data)
            key = self._generate_key(checksum)
            print("storing in redis")
            self.redis_client.set(key, cache_data_json, ex=self.expiration_time)

            file_key = self._generate_file_key(file_id)
            print("storing uiud in redis")
            self.redis_client.set(file_key, key, ex=self.expiration_time)
            return True
        except Exception as e:
            print(f"Redis storage error: {str(e)}")
            return False

    def get_analysis(self, checksum: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached analysis results for a file checksum.

        Args:
            checksum (str): File checksum

        Returns:
            dict: Cached analysis results or None if not found
        """
        try:
            key = self._generate_key(checksum)
            cached_data = self.redis_client.get(key)

            if not cached_data:
                return None

            # Convert from JSON string to dictionary
            return json.loads(cached_data)
        except Exception as e:
            print(f"Redis retrieval error: {str(e)}")
            return None

    def get_analysis_file_id(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached analysis results for a file id.
        """
        try:
            key = self._generate_file_key(file_id)
            checksum_key = self.redis_client.get(key)
            if not checksum_key:
                print("Checksum not found", key)
                return None
            cached_data = self.redis_client.get(checksum_key)
            if not cached_data:
                print("cache not found", checksum_key)
                return None
            return json.loads(cached_data)
        except Exception as e:
            print(f"Redis retrieval error: {str(e)}")
            return None

    def exists(self, checksum: str) -> bool:
        """
        Check if analysis results exist for a file checksum.

        Args:
            checksum (str): File checksum

        Returns:
            bool: True if results exist in cache
        """
        key = self._generate_key(checksum)
        return self.redis_client.exists(key) > 0

    def delete(self, checksum: str) -> bool:
        """
        Delete cached analysis results for a file checksum.

        Args:
            checksum (str): File checksum

        Returns:
            bool: True if deletion was successful
        """
        try:
            key = self._generate_key(checksum)
            self.redis_client.delete(key)
            return True
        except Exception as e:
            print(f"Redis deletion error: {str(e)}")
            return False


def calculate_file_checksum(file_path: str, algorithm="sha256") -> str:
    """
    Calculate checksum for a file.

    Args:
        file_path (str): Path to the file
        algorithm (str): Hash algorithm to use

    Returns:
        str: Checksum as a hexadecimal string
    """
    if algorithm == "md5":
        hash_func = hashlib.md5()
    elif algorithm == "sha1":
        hash_func = hashlib.sha1()
    elif algorithm == "sha512":
        hash_func = hashlib.sha512()
    else:
        hash_func = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()
