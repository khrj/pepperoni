import os
import tempfile
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
from pydantic import BaseModel, Field
import uvicorn
from typing import Optional

# Import the analysis functions from the provided code
import dpkt
from collections import Counter, defaultdict

from core.redis_cache import RedisCache, calculate_file_checksum
from core.pcap_analyze import save_analysis_to_json, analyze_pcap


# Create Redis cache instance
# These settings can be moved to environment variables or config file
redis_cache = RedisCache(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD", None),
    expiration_time=int(os.getenv("REDIS_EXPIRATION", "86400")),  # 24 hours
)


# Create FastAPI app
app = FastAPI(
    title="Network Packet Analyzer API",
    description="API for analyzing network packet captures (PCAP files)",
    version="1.0.0",
)

# Add CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "message": "Welcome to the Network Packet Analyzer API. Use POST /analyze to analyze a PCAP file."
    }


@app.post("/analyze")
async def analyze_pcap_file(
    pcap_file: UploadFile = File(...), baseline_file: Optional[UploadFile] = None
):
    """
    Analyze a PCAP file and return the results as JSON.

    - **pcap_file**: The PCAP file to analyze
    - **baseline_file**: Optional baseline PCAP file for comparison
    """
    try:
        # Create temporary files to store the uploaded files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        # Calculate checksum for the file
        file_checksum = calculate_file_checksum(pcap_path)

        # Check if analysis already exists in cache
        cached_analysis = redis_cache.get_analysis(file_checksum)
        if cached_analysis:
            # Clean up the temp file
            os.unlink(pcap_path)

            print(f"Cache hit for checksum: {file_checksum}")
            return JSONResponse(content=cached_analysis["analysis_results"])

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        # Analyze the PCAP file
        analysis_results = analyze_pcap(pcap_path, baseline_path)

        # Store the analysis results in cache
        file_id = str(uuid.uuid4())
        analysis_results["file_id"] = file_id
        print("Saving analysis to cache...")
        redis_cache.store_analysis(file_checksum, file_id, analysis_results)

        # Clean up temporary files
        print("Cleaning temp files")
        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        save_analysis_to_json(analysis_results, "analysis_results.json")
        return JSONResponse(content=analysis_results)

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error analyzing PCAP file: {str(e)}"
        )


@app.post("/save-analysis")
async def save_analysis(
    pcap_file: UploadFile = File(...),
    output_filename: str = Form("network_analysis.json"),
    baseline_file: Optional[UploadFile] = None,
):
    """
    Analyze a PCAP file and save the results to a JSON file.

    - **pcap_file**: The PCAP file to analyze
    - **output_filename**: Name of the output JSON file
    - **baseline_file**: Optional baseline PCAP file for comparison
    """
    try:
        # Create temporary files to store the uploaded files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        # Analyze the PCAP file
        analysis_results = analyze_pcap(pcap_path, baseline_path)

        # Save the analysis results to a JSON file
        save_analysis_to_json(analysis_results, output_filename)

        # Clean up temporary files
        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        return {"message": f"Analysis complete! Results saved to {output_filename}"}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error analyzing PCAP file: {str(e)}"
        )




@app.post("/get_packets")
async def get_packets(
    file_id: Optional[str] = None, num_packets: int = 100, start_index: int = 0
):
    # Check if analysis already exists in cache
    print("File id", file_id)
    if file_id is None:
        return {"message": "file_id required"}
    cached_analysis = redis_cache.get_analysis_file_id(file_id)
    if cached_analysis:
        packets = cached_analysis["analysis_results"]["packetData"]
        return packets[start_index : start_index + num_packets]
    else:
        return {"message": "Analysis not found in cache"}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

    # Testing LLM
    # packets = process_pcap("sample2.pcapng")
    # insights_data = get_insights_data(packets)

    # print(insights_data)
