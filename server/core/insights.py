from datetime import datetime
import json
import os

# Configure Gemini
from openai import OpenAI


from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GEMINI_KEY"),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
)


def get_insights_data(packets):
    """
    Generate LLM-powered insights from raw packet data using Gemini

    Args:
        packets: List of packet dictionaries

    Returns:
        Dictionary containing insights and correlations
    """
    if not packets:
        return {"insights": [], "correlations": []}

    def simplify_packets_for_llm(packets, max_packets=1500):
        """
        Create a condensed version of packet data suitable for LLM analysis

        Args:
            packets: List of packets from process_pcap
            max_packets: Maximum number of packets to include (for context limits)

        Returns:
            List of simplified packet dictionaries
        """
        simplified = []

        for pkt in packets[:max_packets]:
            # Base information
            simplified_pkt = {
                "timestamp": datetime.fromtimestamp(pkt["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "protocol": pkt["protocol"],
                "size": pkt["size"],
                "source": f"{pkt['src_ip']}:{pkt.get('src_port', 0)}",
                "destination": f"{pkt['dst_ip']}:{pkt.get('dst_port', 0)}",
            }

            # Protocol-specific additions
            if pkt["protocol"] == "TCP":
                simplified_pkt.update(
                    {
                        "flags": {
                            "retransmission": pkt.get("is_retransmission", False),
                        }
                    }
                )

            if pkt["protocol"] == "MQTT":
                simplified_pkt.update(
                    {
                        "mqtt": {
                            "type": pkt.get("mqtt_type", 0),
                            "qos": pkt.get("mqtt_qos", 0),
                        }
                    }
                )

            # Remove unnecessary fields
            simplified_pkt.pop("raw_payload", None)

            simplified.append(simplified_pkt)

        return simplified

    packets = simplify_packets_for_llm(packets)

    FRONTEND = """<div>
				<h2 className="text-xl font-bold mb-4">Root Cause Analysis</h2>
				<div className="grid gap-4 md:grid-cols-2">
					{insightsData.correlations.map(correlation => (
						<Card key={correlation.id}>
							<CardHeader>
								<CardTitle>{correlation.title}</CardTitle>
								<CardDescription>{correlation.description}</CardDescription>
							</CardHeader>
							<CardContent>
								<ResponsiveContainer width="100%" height={300}>
									<BarChart
										data={correlation.data}
										margin={{
											top: 5,
											right: 30,
											left: 20,
											bottom: 5,
										}}
									>
										<CartesianGrid strokeDasharray="3 3" />
										<XAxis dataKey={correlation.id === 1 ? "size" : "protocol"} />
										<YAxis
											label={{
												value: "Delay (ms)",
												angle: -90,
												position: "insideLeft",
											}}
										/>
										<Tooltip />
										<Bar dataKey="count" fill="#f4735b" />
									</BarChart>
								</ResponsiveContainer>
							</CardContent>
						</Card>
					))}
				</div>
			</div>"""

    # Construct the LLM prompt
    # print(packets)
    prompt = f"""Analyze these network packets and generate network insights in exactly this JSON format:
{json.dumps(packets, indent=2)}

Output Requirements:
1. insights (max 3 items) with:
- id: sequential number
- title: short problem title
- description: concise explanation with specific metrics
- severity: low/medium/high/critical
- impact: percentage or qualitative
- type: bottleneck/error/recommendation

2. correlations (max 2 items) with:
- id: sequential number
- title: correlation title  
- description: statistical relationship
- data: supporting metrics

Look for:
- Major issues and bottlenecks in the network
- Broker delays (MQTT PUBLISH/PUBACK timing)
- Retransmission patterns
- Packet size vs timing correlations
- Protocol/QoS performance differences
- Network congestion patterns
- The data provided by the correlations should be compatible with the frontend as shown below:
    {FRONTEND}

Example insight: {{
  "id": 1,
  "title": "Broker Processing Bottleneck",
  "description": "Average 250ms delay observed between MQTT PUBLISH (type 3) and PUBACK (type 4) packets",
  "severity": "high",
  "impact": "Affects 15% of packets",
  "type": "bottleneck"
}}

Example correlation: {{
    "id": 1,
    "title": "Packet Size and Retransmission",
    "description": "The retransmission primarily affects packets with size 74, highlighting an issue with smaller packets being dropped.",
    "data": [
        {{
            "size": "74",
            "count": 104
        }},
        {{
            "size": "96",
            "count": 6
        }},
        {{
            "size": "102",
            "count": 8
        }}
    ]
}}

Return ONLY valid JSON with double quotes. No markdown formatting:"""
    # print("Length of prompt: ", len(prompt))

    try:
        # Get Gemini response
        response = client.chat.completions.create(
            model="gemini-2.0-flash",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt},
            ],
        )

        response = response.choices[0].message.content
        cleaned = response.strip().replace("```json", "").replace("```", "")

        # Parse and validate
        result = json.loads(cleaned)

        # Convert data values to numeric if needed
        for corr in result.get("correlations", []):
            if isinstance(corr["data"], dict):
                for k, v in corr["data"].items():
                    if isinstance(v, str) and "ms" in v:
                        corr["data"][k] = float(v.replace("ms", "").strip())

        return {
            "insights": result.get("insights", [])[:3],
            "correlations": result.get("correlations", [])[:2],
        }

    except Exception as e:
        print(f"LLM analysis failed: {str(e)}")
        return {"insights": [], "correlations": []}
