"use client"

import { useEffect, useState } from "react"
import { MoreHorizontal } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
	DynamicPaginationItems,
	Pagination,
	PaginationContent,
	PaginationEllipsis,
	PaginationItem,
	PaginationLink,
	PaginationNext,
	PaginationPrevious,
} from "@/components/ui/pagination"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"

export default function PacketsPage() {
	const [selectedProtocol, setSelectedProtocol] = useState("all")
	const [selectedDelay, setSelectedDelay] = useState("all")
	const [currentPage, setCurrentPage] = useState(1)
	const [selectedPacket, setSelectedPacket] = useState<any>(null)

	const [packetData, setPacketData] = useState(null)

	useEffect(() => {
		const analysisResults = JSON.parse(localStorage.getItem("analysisResults") || "{}")
		setPacketData(analysisResults.packetData || {})
	}, [])

	if (!packetData) {
		return <div>Loading...</div>
	}

	const itemsPerPage = 10

	// Filter packets
	const filteredPackets = packetData.filter(packet => {
		const matchesProtocol = selectedProtocol === "all" || packet.protocol === selectedProtocol

		let matchesDelay = true
		if (selectedDelay === "high") {
			matchesDelay = packet.delay > 300
		} else if (selectedDelay === "medium") {
			matchesDelay = packet.delay >= 100 && packet.delay <= 300
		} else if (selectedDelay === "low") {
			matchesDelay = packet.delay < 100
		}

		return matchesProtocol && matchesDelay
	})

	// Pagination
	const totalPages = Math.ceil(filteredPackets.length / itemsPerPage)
	const paginatedPackets = filteredPackets.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

	const getDelayClass = (delay: number) => {
		if (delay > 300) return "bg-red-500 text-white dark:bg-red-700 dark:text-white rounded-full px-2 py-1"
		if (delay > 200) return "bg-black text-white dark:bg-gray-800 dark:text-white rounded-full px-2 py-1"
		return ""
	}

	return (
		<div className="space-y-4">
			<div className="flex justify-between items-center">
				<h1 className="text-2xl font-bold">Packet Details</h1>
				<div className="flex gap-2">
					<Select value={selectedProtocol} onValueChange={setSelectedProtocol}>
						<SelectTrigger className="w-[150px]">
							<SelectValue placeholder="All Protocols" />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="all">All Protocols</SelectItem>
							<SelectItem value="MQTT">MQTT</SelectItem>
							<SelectItem value="TCP">TCP</SelectItem>
							<SelectItem value="UDP">UDP</SelectItem>
							<SelectItem value="DNS">DNS</SelectItem>
						</SelectContent>
					</Select>

					<Select value={selectedDelay} onValueChange={setSelectedDelay}>
						<SelectTrigger className="w-[150px]">
							<SelectValue placeholder="All Delays" />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="all">All Delays</SelectItem>
							<SelectItem value="high">High Delay</SelectItem>
							<SelectItem value="medium">Medium Delay</SelectItem>
							<SelectItem value="low">Low Delay</SelectItem>
						</SelectContent>
					</Select>
				</div>
			</div>

			<Card>
				<CardContent className="p-0">
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead className="w-[50px]">ID</TableHead>
								<TableHead>Timestamp</TableHead>
								<TableHead>Protocol</TableHead>
								<TableHead>Source</TableHead>
								<TableHead>Destination</TableHead>
								<TableHead className="text-right">Size (bytes)</TableHead>
								<TableHead className="text-right">Delay (ms)</TableHead>
								<TableHead>Delay Category</TableHead>
								<TableHead className="w-[50px]"></TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{paginatedPackets.map(packet => (
								<TableRow
									key={packet.id}
									onClick={() => setSelectedPacket(packet)}
									className="cursor-pointer"
								>
									<TableCell>{packet.id}</TableCell>
									<TableCell>{packet.timestamp}</TableCell>
									<TableCell>{packet.protocol}</TableCell>
									<TableCell>{packet.source}</TableCell>
									<TableCell>{packet.destination}</TableCell>
									<TableCell className="text-right">{packet.size}</TableCell>
									<TableCell className="text-right">
										<span className={getDelayClass(packet.delay)}>{packet.delay}</span>
									</TableCell>
									<TableCell>{packet.delayCategory}</TableCell>
									<TableCell>
										<Button variant="ghost" size="icon">
											<MoreHorizontal className="h-4 w-4" />
										</Button>
									</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>

					<div className="p-4 flex justify-end">
						<Pagination>
							<PaginationContent>
								<PaginationItem>
									<PaginationPrevious
										onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
										disabled={currentPage === 1}
									/>
								</PaginationItem>

								<DynamicPaginationItems
									currentPage={currentPage}
									totalPages={totalPages}
									setCurrentPage={setCurrentPage}
								/>

								<PaginationItem>
									<PaginationNext
										onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
										disabled={currentPage === totalPages}
									/>
								</PaginationItem>
							</PaginationContent>
						</Pagination>
					</div>
				</CardContent>
			</Card>

			<Dialog open={!!selectedPacket} onOpenChange={open => !open && setSelectedPacket(null)}>
				<DialogContent className="max-w-3xl">
					<DialogHeader>
						<DialogTitle>Packet Details #{selectedPacket?.id}</DialogTitle>
						<DialogDescription>Detailed information about the selected packet</DialogDescription>
					</DialogHeader>

					{selectedPacket && (
						<div className="grid grid-cols-1 gap-4 md:grid-cols-2">
							<div>
								<h3 className="mb-2 font-semibold">Basic Information</h3>
								<div className="space-y-2 rounded-md border p-4">
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Timestamp:</span>
										<span className="col-span-2 text-sm">{selectedPacket.timestamp}</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Protocol:</span>
										<span className="col-span-2 text-sm">{selectedPacket.protocol}</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Source:</span>
										<span className="col-span-4 text-sm">{selectedPacket.source}</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Destination:</span>
										<span className="col-span-4 text-sm">{selectedPacket.destination}</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Size:</span>
										<span className="col-span-2 text-sm">{selectedPacket.size} bytes</span>
									</div>
								</div>
							</div>

							<div>
								<h3 className="mb-2 font-semibold">Delay Information</h3>
								<div className="space-y-2 rounded-md border p-4">
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Delay:</span>
										<span className="col-span-2 text-sm">{selectedPacket.delay} ms</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Category:</span>
										<span className="col-span-2 text-sm">{selectedPacket.delayCategory}</span>
									</div>
									<div className="grid grid-cols-3 gap-2">
										<span className="text-sm font-medium">Severity:</span>
										<span className="col-span-2 text-sm">
											{selectedPacket.delay > 300
												? "High"
												: selectedPacket.delay > 200
												? "Medium"
												: "Low"}
										</span>
									</div>
								</div>
							</div>
						</div>
					)}
				</DialogContent>
			</Dialog>
		</div>
	)
}
