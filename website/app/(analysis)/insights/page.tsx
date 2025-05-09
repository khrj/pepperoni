"use client"

import { AlertCircle, AlertTriangle, Info } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"
import { useEffect, useState } from "react"


export default function InsightsPage() {
	const [insightsData, setInsightsData] = useState(null)

	useEffect(() => {
		const analysisResults = JSON.parse(localStorage.getItem("analysisResults") || "{}")
		setInsightsData(analysisResults.insightsData || {})
	}, [])

	if (!insightsData) {
		return <div>Loading...</div>
	}

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
				{insightsData.insights.map(insight => (
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
											bottom: 20,
										}}
									>
										<CartesianGrid strokeDasharray="3 3" />
										<XAxis
											dataKey={"size" in correlation.data[0] ? "size" : "protocol"}
											label={{
												value: "size" in correlation.data[0] ? "Size" : "Protocol",
												position: "bottom",
											}}
										/>
										<YAxis
											label={{
												value: "Count",
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
			</div>
		</div>
	)
}
