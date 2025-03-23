"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Clock, Filter, LayoutDashboard, LineChart, Moon, Pizza, Plus, Search, Sun } from "lucide-react"
import { usePathname, useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useTheme } from "next-themes"
import { Badge } from "@/components/ui/badge"
import { generatePDF } from "@/lib/pdf-export"

export default function AnalysisLayout({ children }: { children: React.ReactNode }) {
	const pathname = usePathname()
	const router = useRouter()
	const { theme, setTheme } = useTheme()
	const [mounted, setMounted] = useState(false)

	const [analysisResults, setAnalysisResults] = useState(null)

	useEffect(() => {
		const analysisResults = JSON.parse(localStorage.getItem("analysisResults") || "{}")
		setAnalysisResults(analysisResults)
	}, [])

	// Avoid hydration mismatch
	useEffect(() => {
		setMounted(true)
	}, [])

	const handleExportReport = () => {
		// Implementation for exporting report
		console.log("Exporting report...")

		// try {
		//   generatePDF(data, "dashboard").then((pdfBlob) => {
		//     const url = URL.createObjectURL(pdfBlob);
		//     const a = document.createElement("a");
		//     a.href
		//       = url;
		//     a.download = "mqtt-analysis-report.pdf";
		//     document.body.appendChild(a);
		//     a.click();
		//     URL.revokeObjectURL(url);
		//   }
		// }
		//   catch (error) {
		//     console.error("Error generating PDF:", error);
		//   }

		// try {

		//   const pdfBlob = await generatePDF(data, "dashboard");
		//   const url = URL.createObjectURL(pdfBlob);
		//   const a = document.createElement("a");
		//   a.href = url;
		//   a.download = "mqtt-analysis-report.pdf";
		//   document.body.appendChild(a);
		//   a.click();
		//   URL.revokeObjectURL(url);
		// } catch (error) {
		//   console.error("Error generating PDF:", error);
		// }
	}

	return (
		<div className="min-h-screen flex flex-col">
			<header className="border-b bg-background">
				<div className="container mx-auto px-4 h-14 flex items-center justify-between">
					<div className="flex items-center gap-2">
						{/* <Clock className="h-6 w-6" /> */}
						<Pizza className="h-6 w-6" />
						<span className="text-lg font-bold">Pepperoni</span>
					</div>

					<div className="flex items-center gap-4">
						<Badge
							variant="outline"
							className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100"
						>
							Analysis Complete
						</Badge>
						{analysisResults && (
							<>
								<Badge variant="outline">{analysisResults.summaryData.numPackets} Packets</Badge>
								<Badge variant="outline">{analysisResults.protocolDistribution.length} Protocols</Badge>
							</>
						)}
						<Button
							variant="outline"
							size="sm"
							onClick={() => {
								router.push("/")
							}}
						>
							<Plus className="h-6 w-6" />
							Upload New
						</Button>
						{mounted && (
							<Button
								variant="ghost"
								size="icon"
								onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
							>
								{theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
								<span className="sr-only">Toggle theme</span>
							</Button>
						)}
					</div>
				</div>
			</header>

			<div className="container mx-auto px-4 py-4">
				<div className="flex justify-between items-center mb-4">
					<div className="bg-muted rounded-lg p-1 flex">
						<Button
							variant={pathname === "/dashboard" ? "default" : "ghost"}
							className="rounded-lg"
							onClick={() => router.push("/dashboard")}
						>
							<LayoutDashboard className="h-4 w-4 mr-2" />
							Dashboard
						</Button>
						<Button
							variant={pathname === "/packets" ? "default" : "ghost"}
							className="rounded-lg"
							onClick={() => router.push("/packets")}
						>
							<LineChart className="h-4 w-4 mr-2" />
							Packet Details
						</Button>
						<Button
							variant={pathname === "/insights" ? "default" : "ghost"}
							className="rounded-lg"
							onClick={() => router.push("/insights")}
						>
							<LineChart className="h-4 w-4 mr-2" />
							Insights
						</Button>
					</div>
				</div>

				{children}
			</div>
		</div>
	)
}
