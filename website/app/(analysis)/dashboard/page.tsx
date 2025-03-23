"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
	Bar,
	BarChart,
	CartesianGrid,
	Pie,
	PieChart,
	XAxis,
	YAxis,
	Tooltip,
	Legend,
	Area,
	AreaChart,
	Cell,
	ResponsiveContainer,
} from "recharts"

export default function DashboardPage() {
	const [summaryData, setSummaryData] = useState(null)
	const [protocolDistribution, setProtocolDistribution] = useState([])
	const [delayCategories, setDelayCategories] = useState([])
	const [latencyTrends, setLatencyTrends] = useState([])
	const [delayTimeline, setDelayTimeline] = useState([])

	useEffect(() => {
		const analysisResults = JSON.parse(localStorage.getItem("analysisResults") || "{}")
		setSummaryData(analysisResults.summaryData || {})
		setProtocolDistribution(analysisResults.protocolDistribution || [])
		setDelayCategories(analysisResults.delayCategories || [])
		setLatencyTrends(analysisResults.latencyTrends || [])
		setDelayTimeline(analysisResults.delayTimeline || [])
	}, [])

	// Colors for charts
	const COLORS = {
		mqtt: "#f4735b",
		tcp: "#45b7a9",
		udp: "#fac858",
		dns: "#5470c6",
		brokerProcessing: "#f4735b",
		network: "#45b7a9",
		bundlingDelay: "#5470c6",
		retransmission: "#fac858",
	}

	if (!summaryData) {
		return <div>Loading...</div>
	}

	return (
		<div className="space-y-4">
			<div className="grid gap-4 grid-cols-1 md:grid-cols-3">
				<Card>
					<CardContent className="p-6">
						<div className="space-y-2">
							<h3 className="text-sm font-medium">Average Latency</h3>
							<p className="text-3xl font-bold">{summaryData.avgLatency} ms</p>
							<p className="text-xs text-muted-foreground">
								Time taken for packets to travel between source and destination
							</p>
							<div className="h-2 bg-muted rounded-full overflow-hidden">
								<div
									className="h-full bg-primary"
									style={{
										width: `${(summaryData.avgLatency / 500) * 100}%`,
									}}
								/>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardContent className="p-6">
						<div className="space-y-2">
							<h3 className="text-sm font-medium">Packet Loss</h3>
							<p className="text-3xl font-bold">{summaryData.packetLoss}%</p>
							<p className="text-xs text-muted-foreground">
								Percentage of packets that fail to reach destination.
							</p>
							<div className="h-2 bg-muted rounded-full overflow-hidden">
								<div
									className="h-full bg-primary"
									style={{
										width: `${(summaryData.packetLoss / 5) * 100}%`,
									}}
								/>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardContent className="p-6">
						<div className="space-y-2">
							<h3 className="text-sm font-medium">Jitter</h3>
							<p className="text-3xl font-bold">{summaryData.jitter} ms</p>
							<p className="text-xs text-muted-foreground">Variation in packet delay over time.</p>
							<div className="h-2 bg-muted rounded-full overflow-hidden">
								<div
									className="h-full bg-primary"
									style={{
										width: `${(summaryData.jitter / 50) * 100}%`,
									}}
								/>
							</div>
						</div>
					</CardContent>
				</Card>
			</div>

			<div className="grid gap-4 grid-cols-1 md:grid-cols-2">
				<Card>
					<CardHeader className="pb-2">
						<CardTitle className="text-base">Protocol Distribution</CardTitle>
						<CardDescription>Breakdown of protocols in the capture</CardDescription>
					</CardHeader>
					<CardContent className="h-[300px] justify-center align-middle">
						<ResponsiveContainer width="100%" height={300}>
							<PieChart>
								<Pie
									className="outline-none"
									data={protocolDistribution}
									cx="50%"
									cy="50%"
									innerRadius={0}
									outerRadius={75}
									fill="#8884d8"
									paddingAngle={0}
									dataKey="value"
									label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
								>
									{protocolDistribution.map((entry, index) => (
										<Cell
											className="outline-none"
											key={`cell-${index}`}
											fill={
												entry.name === "MQTT"
													? COLORS.mqtt
													: entry.name === "TCP"
													? COLORS.tcp
													: entry.name === "UDP"
													? COLORS.udp
													: COLORS.dns
											}
										/>
									))}
								</Pie>
								<Tooltip formatter={value => `${value}%`} />
							</PieChart>
						</ResponsiveContainer>
					</CardContent>
				</Card>

				<Card>
					<CardHeader className="pb-2">
						<CardTitle className="text-base">Delay Categories</CardTitle>
						<CardDescription>Classification of delay types</CardDescription>
					</CardHeader>
					<CardContent className="h-[300px]">
						<ResponsiveContainer height={300} width="100%">
							<PieChart>
								<Pie
									className="outline-none"
									data={delayCategories}
									cx="50%"
									cy="50%"
									innerRadius={0}
									outerRadius={75}
									fill="#8884d8"
									paddingAngle={0}
									dataKey="value"
									label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
								>
									{delayCategories.map((entry, index) => (
										<Cell
											className="outline-none"
											key={`cell-${index}`}
											fill={
												entry.name === "Broker Processing"
													? COLORS.brokerProcessing
													: entry.name === "Network"
													? COLORS.network
													: entry.name === "Bundling Delay"
													? COLORS.bundlingDelay
													: COLORS.retransmission
											}
										/>
									))}
								</Pie>
								<Tooltip formatter={value => `${value}%`} />
							</PieChart>
						</ResponsiveContainer>
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Latency Trends</CardTitle>
					<CardDescription>Packet latency over time</CardDescription>
				</CardHeader>
				<CardContent className="h-[300px]">
					<ResponsiveContainer width="100%" height={300}>
						<AreaChart data={latencyTrends} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
							<defs>
								<linearGradient id="colorMqtt" x1="0" y1="0" x2="0" y2="1">
									<stop offset="5%" stopColor={COLORS.mqtt} stopOpacity={0.8} />
									<stop offset="95%" stopColor={COLORS.mqtt} stopOpacity={0.1} />
								</linearGradient>
								<linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
									<stop offset="5%" stopColor={COLORS.tcp} stopOpacity={0.8} />
									<stop offset="95%" stopColor={COLORS.tcp} stopOpacity={0.1} />
								</linearGradient>
							</defs>
							<XAxis dataKey="time" />
							<YAxis />
							<CartesianGrid strokeDasharray="3 3" />
							<Tooltip />
							<Area
								type="monotone"
								dataKey="mqtt"
								stroke={COLORS.mqtt}
								fillOpacity={1}
								fill="url(#colorMqtt)"
							/>
							<Area
								type="monotone"
								dataKey="tcp"
								stroke={COLORS.tcp}
								fillOpacity={1}
								fill="url(#colorTcp)"
							/>
						</AreaChart>
					</ResponsiveContainer>
				</CardContent>
			</Card>

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Delay Timeline</CardTitle>
					<CardDescription>Visualization of packet delays across the capture period</CardDescription>
				</CardHeader>
				<CardContent className="h-[300px]">
					<ResponsiveContainer width="100%" height={300}>
						<BarChart data={delayTimeline} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
							<CartesianGrid strokeDasharray="3 3" />
							<XAxis dataKey="time" />
							<YAxis />
							<Tooltip />
							<Legend />
							<Bar dataKey="mqtt" name="MQTT" fill={COLORS.mqtt} />
							<Bar dataKey="tcp" name="TCP" fill={COLORS.tcp} />
							<Bar dataKey="udp" name="UDP" fill={COLORS.udp} />
						</BarChart>
					</ResponsiveContainer>
				</CardContent>
			</Card>
		</div>
	)
}
