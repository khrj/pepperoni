"use client"

import { AlertCircle, AlertTriangle, Info } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, Tooltip } from "recharts"

// Dummy insights data
const insightsData = {
  insights: [
    {
      id: 1,
      title: "Broker Processing Bottleneck",
      description:
        "Detected significant delays (avg. 320ms) during broker processing. This appears to be caused by excessive packet aggregation before forwarding.",
      severity: "high",
      impact: "Affects 42% of packets",
      type: "bottleneck",
    },
    {
      id: 2,
      title: "Retransmission Spikes",
      description:
        "Multiple retransmission events detected between 14:32-14:45, indicating network congestion or packet loss. This is causing delays of up to 1.2s for affected packets.",
      severity: "critical",
      impact: "Affects 8% of packets",
      type: "error",
    },
    {
      id: 3,
      title: "Bundle Size Optimization",
      description:
        "Current bundle size (avg. 24 packets) is causing unnecessary delays. Analysis suggests optimal bundle size of 12-15 packets would reduce latency by approximately 40%.",
      severity: "medium",
      impact: "Recommendation",
      type: "recommendation",
    },
  ],
  correlations: [
    {
      id: 1,
      title: "Packet Size vs Delay",
      description: "Strong positive correlation (r=0.78) between packet size and processing delay",
      data: [
        { size: "64", delay: 75 },
        { size: "128", delay: 110 },
        { size: "256", delay: 180 },
        { size: "512", delay: 250 },
        { size: "1024", delay: 350 },
      ],
    },
    {
      id: 2,
      title: "Protocol vs Delay",
      description: "MQTT QoS 2 packets show 3.2x higher delay than QoS 0 packets",
      data: [
        { protocol: "MQTT QoS 0", delay: 85 },
        { protocol: "MQTT QoS 1", delay: 180 },
        { protocol: "MQTT QoS 2", delay: 270 },
        { protocol: "TCP", delay: 95 },
        { protocol: "UDP", delay: 45 },
      ],
    },
  ],
}

export default function InsightsPage() {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-50 border-red-200 text-red-800 dark:bg-red-950 dark:border-red-900 dark:text-red-300"
      case "high":
        return "bg-amber-50 border-amber-200 text-amber-800 dark:bg-amber-950 dark:border-amber-900 dark:text-amber-300"
      case "medium":
        return "bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-950 dark:border-blue-900 dark:text-blue-300"
      default:
        return "bg-gray-50 border-gray-200 text-gray-800 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-300"
    }
  }

  const getSeverityIcon = (type: string) => {
    switch (type) {
      case "error":
        return <AlertCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
      case "bottleneck":
        return <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400" />
      case "recommendation":
        return <Info className="h-5 w-5 text-blue-600 dark:text-blue-400" />
      default:
        return <Info className="h-5 w-5" />
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
      case "high":
        return "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300"
      case "medium":
        return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-2">Delay Insights</h1>
        <p className="text-muted-foreground">Automated analysis of delay patterns and anomalies</p>
      </div>

      <div className="space-y-4">
        {insightsData.insights.map((insight) => (
          <div key={insight.id} className={`border rounded-lg p-4 ${getSeverityColor(insight.severity)}`}>
            <div className="flex items-start gap-3">
              {getSeverityIcon(insight.type)}
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">{insight.title}</h3>
                  <div className="flex gap-2">
                    <Badge className={getSeverityBadge(insight.severity)}>
                      {insight.severity === "critical"
                        ? "Critical"
                        : insight.severity === "high"
                          ? "High Impact"
                          : insight.severity === "medium"
                            ? "Medium Impact"
                            : "Low Impact"}
                    </Badge>
                    <Badge variant="outline">{insight.impact}</Badge>
                  </div>
                </div>
                <p className="mt-1">{insight.description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div>
        <h2 className="text-xl font-bold mb-4">Root Cause Analysis</h2>
        <div className="grid gap-4 md:grid-cols-2">
          {insightsData.correlations.map((correlation) => (
            <Card key={correlation.id}>
              <CardHeader>
                <CardTitle>{correlation.title}</CardTitle>
                <CardDescription>{correlation.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <BarChart
                  width={400}
                  height={300}
                  data={correlation.data}
                  margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey={correlation.id === 1 ? "size" : "protocol"} />
                  <YAxis label={{ value: "Delay (ms)", angle: -90, position: "insideLeft" }} />
                  <Tooltip />
                  <Bar dataKey="delay" fill="#f4735b" />
                </BarChart>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}

