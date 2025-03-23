from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
from ..core.analysis import analyze_pcap
from ..core.utils import save_analysis_to_json

router = APIRouter()

# Add CORS middleware
router.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@router.get("/")
async def root():
    return {
        "message": "Welcome to the Network Packet Analyzer API. Use POST /analyze to analyze a PCAP file."
    }

@router.post("/analyze")
async def analyze_pcap_file(
    pcap_file: UploadFile = File(...), 
    baseline_file: UploadFile = None
):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        analysis_results = analyze_pcap(pcap_path, baseline_path)

        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        return JSONResponse(content=analysis_results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing PCAP file: {str(e)}")

@router.post("/save-analysis")
async def save_analysis(
    pcap_file: UploadFile = File(...),
    output_filename: str = Form("network_analysis.json"),
    baseline_file: UploadFile = None,
):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        analysis_results = analyze_pcap(pcap_path, baseline_path)
        save_analysis_to_json(analysis_results, output_filename)

        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        return {"message": f"Analysis complete! Results saved to {output_filename}"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing PCAP file: {str(e)}")