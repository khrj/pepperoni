"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
} from "recharts";

// Dummy data
const summaryData = {
  avgLatency: 245, // ms
  packetLoss: 2.4, // %
  jitter: 18, // ms
  baseline: {
    avgLatency: 210,
    packetLoss: 1.8,
    jitter: 15,
  },
};

const protocolDistribution = [
  { name: "MQTT", value: 65 },
  { name: "TCP", value: 20 },
  { name: "UDP", value: 10 },
  { name: "DNS", value: 5 },
];

const delayCategories = [
  { name: "Broker Processing", value: 42 },
  { name: "Network", value: 28 },
  { name: "Bundling Delay", value: 18 },
  { name: "Retransmission", value: 12 },
];

const latencyTrends = [
  { time: "14:00", mqtt: 220, tcp: 180 },
  { time: "14:10", mqtt: 250, tcp: 190 },
  { time: "14:20", mqtt: 280, tcp: 200 },
  { time: "14:30", mqtt: 450, tcp: 220 },
  { time: "14:40", mqtt: 350, tcp: 210 },
  { time: "14:50", mqtt: 300, tcp: 200 },
  { time: "15:00", mqtt: 280, tcp: 190 },
  { time: "15:10", mqtt: 260, tcp: 185 },
  { time: "15:20", mqtt: 240, tcp: 180 },
  { time: "15:30", mqtt: 230, tcp: 175 },
];

const delayTimeline = [
  { time: "14:00", mqtt: 120, tcp: 80, udp: 45 },
  { time: "14:10", mqtt: 150, tcp: 90, udp: 50 },
  { time: "14:20", mqtt: 180, tcp: 100, udp: 55 },
  { time: "14:30", mqtt: 350, tcp: 120, udp: 60 },
  { time: "14:40", mqtt: 250, tcp: 110, udp: 55 },
  { time: "14:50", mqtt: 200, tcp: 100, udp: 50 },
  { time: "15:00", mqtt: 180, tcp: 90, udp: 45 },
  { time: "15:10", mqtt: 160, tcp: 85, udp: 40 },
  { time: "15:20", mqtt: 140, tcp: 80, udp: 35 },
  { time: "15:30", mqtt: 130, tcp: 75, udp: 30 },
];

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
};

export default function DashboardPage() {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 grid-cols-1 md:grid-cols-3">
        <Card>
          <CardContent className="p-6">
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Average Latency</h3>
              <p className="text-3xl font-bold">{summaryData.avgLatency} ms</p>
              <p className="text-xs text-muted-foreground">
                {(
                  (summaryData.avgLatency / summaryData.baseline.avgLatency -
                    1) *
                  100
                ).toFixed(1)}
                % from baseline
              </p>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary"
                  style={{ width: `${(summaryData.avgLatency / 500) * 100}%` }}
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
                {(
                  (summaryData.packetLoss / summaryData.baseline.packetLoss -
                    1) *
                  100
                ).toFixed(1)}
                % from baseline
              </p>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary"
                  style={{ width: `${(summaryData.packetLoss / 5) * 100}%` }}
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
              <p className="text-xs text-muted-foreground">
                {(
                  (summaryData.jitter / summaryData.baseline.jitter - 1) *
                  100
                ).toFixed(1)}
                % from baseline
              </p>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary"
                  style={{ width: `${(summaryData.jitter / 50) * 100}%` }}
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
            <CardDescription>
              Breakdown of protocols in the capture
            </CardDescription>
          </CardHeader>
          <CardContent className="h-[300px] justify-center align-middle">
            <PieChart width={400} height={300}>
              <Pie
                data={protocolDistribution}
                cx="50%"
                cy="50%"
                innerRadius={0}
                outerRadius={75}
                fill="#8884d8"
                paddingAngle={0}
                dataKey="value"
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
              >
                {protocolDistribution.map((entry, index) => (
                  <Cell
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
              <Tooltip formatter={(value) => `${value}%`} />
            </PieChart>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Delay Categories</CardTitle>
            <CardDescription>Classification of delay types</CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <PieChart width={400} height={300}>
              <Pie
                data={delayCategories}
                cx="50%"
                cy="50%"
                innerRadius={0}
                outerRadius={75}
                fill="#8884d8"
                paddingAngle={0}
                dataKey="value"
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
              >
                {delayCategories.map((entry, index) => (
                  <Cell
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
              <Tooltip formatter={(value) => `${value}%`} />
            </PieChart>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Latency Trends</CardTitle>
          <CardDescription>Packet latency over time</CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <AreaChart
            width={1000}
            height={300}
            data={latencyTrends}
            margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
          >
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
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Delay Timeline</CardTitle>
          <CardDescription>
            Visualization of packet delays across the capture period
          </CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <BarChart
            width={1000}
            height={300}
            data={delayTimeline}
            margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="mqtt" name="MQTT" fill={COLORS.mqtt} />
            <Bar dataKey="tcp" name="TCP" fill={COLORS.tcp} />
            <Bar dataKey="udp" name="UDP" fill={COLORS.udp} />
          </BarChart>
        </CardContent>
      </Card>
    </div>
  );
}
