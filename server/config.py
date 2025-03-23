from pydantic import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Network Packet Analyzer API"
    APP_DESCRIPTION: str = "API for analyzing network packet captures (PCAP files)"
    APP_VERSION: str = "1.0.0"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

settings = Settings()