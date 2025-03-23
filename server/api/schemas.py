from pydantic import BaseModel

class AnalysisResult(BaseModel):
    summaryData: dict
    protocolDistribution: list
    delayCategories: list
    latencyTrends: list
    delayTimeline: list
    insightsData: dict
    packetData: list