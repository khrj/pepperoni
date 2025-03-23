"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Clock, Moon, Pizza, Sun, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useRouter } from "next/navigation"
import { useTheme } from "@/hooks/use-theme"

export default function UploadPage() {
	const [isDragging, setIsDragging] = useState(false)
	const [file, setFile] = useState<File | null>(null)
	const [isUploading, setIsUploading] = useState(false)
	const router = useRouter()
	const { theme, setTheme } = useTheme()
	const [mounted, setMounted] = useState(false)

	// Avoid hydration mismatch
	useEffect(() => {
		setMounted(true)
	}, [])

	const handleDragOver = (e: React.DragEvent) => {
		e.preventDefault()
		setIsDragging(true)
	}

	const handleDragLeave = () => {
		setIsDragging(false)
	}

	const handleDrop = (e: React.DragEvent) => {
		e.preventDefault()
		setIsDragging(false)

		if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
			const droppedFile = e.dataTransfer.files[0]
			if (droppedFile.name.endsWith(".pcapng")) {
				setFile(droppedFile)
			} else {
				alert("Please upload a .pcapng file")
			}
		}
	}

	const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		if (e.target.files && e.target.files.length > 0) {
			const selectedFile = e.target.files[0]
			if (selectedFile.name.endsWith(".pcapng")) {
				setFile(selectedFile)
			} else {
				alert("Please upload a .pcapng file")
			}
		}
	}

	const handleAnalyze = async () => {
		if (!file) return

		setIsUploading(true)

		try {
			const formData = new FormData()
			formData.append("pcap_file", file)

			const response = await fetch("http://localhost:8000/analyze", {
				method: "POST",
				body: formData,
			})

			const responseData = await response.json()

			if (response.ok) {
				// Save the response to localStorage
				localStorage.setItem("analysisResults", JSON.stringify(responseData))
				router.push("/dashboard")
			} else {
				alert("Error uploading file")
			}
		} catch (error) {
			console.error("Error:", error)
			alert("Error uploading file")
		} finally {
			setIsUploading(false)
		}
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
			</header>

			<main className="flex-1 flex items-center justify-center p-4">
				<Card className="w-full max-w-md">
					<CardHeader>
						<CardTitle className="text-2xl">Upload Packet Capture</CardTitle>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="space-y-2">
							<label className="text-sm font-medium">Packet Capture File</label>
							<div
								className={`border-2 border-dashed rounded-md p-8 text-center ${
									isDragging ? "border-primary bg-primary/10" : "border-muted-foreground/20"
								}`}
								onDragOver={handleDragOver}
								onDragLeave={handleDragLeave}
								onDrop={handleDrop}
							>
								<Upload className="mx-auto h-10 w-10 text-muted-foreground" />
								<p className="mt-2 text-sm text-muted-foreground">
									Drag and drop your .pcapng file here or click to browse
								</p>
								{file && <p className="mt-2 text-sm font-medium text-primary">{file.name}</p>}
								<input
									id="file-upload"
									type="file"
									accept=".pcapng"
									className="hidden"
									onChange={handleFileChange}
								/>
								<Button
									variant="outline"
									className="mt-4"
									onClick={() => document.getElementById("file-upload")?.click()}
								>
									Browse Files
								</Button>
							</div>
						</div>
						<Button className="w-full" disabled={!file || isUploading} onClick={handleAnalyze}>
							{isUploading ? "Analyzing..." : "Analyze Packet Capture"}
						</Button>
					</CardContent>
				</Card>
			</main>
		</div>
	)
}
