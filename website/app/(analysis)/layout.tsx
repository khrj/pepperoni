"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Clock, Filter, LayoutDashboard, LineChart, Moon, Search, Sun } from "lucide-react"
import { usePathname, useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useTheme } from "next-themes"
import { Badge } from "@/components/ui/badge"

export default function AnalysisLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const pathname = usePathname()
  const router = useRouter()
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = useState(false)

  // Avoid hydration mismatch
  useEffect(() => {
    setMounted(true)
  }, [])

  const handleExportReport = () => {
    // Implementation for exporting report
    console.log("Exporting report...")
  }

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b bg-background">
        <div className="container mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-6 w-6" />
            <span className="text-lg font-bold">MQTT Delay Analyzer</span>
          </div>

          <div className="flex items-center gap-4">
            <Badge variant="outline" className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100">
              Analysis Complete
            </Badge>
            <Badge variant="outline">1,245 Packets</Badge>
            <Badge variant="outline">4 Protocols</Badge>
            <Button variant="outline" size="sm" onClick={handleExportReport}>
              Export Report
            </Button>
            {mounted && (
              <Button variant="ghost" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
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

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input type="search" placeholder="Search packets..." className="pl-8 w-[250px]" />
            </div>
            <Button variant="outline" size="icon">
              <Filter className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {children}
      </div>
    </div>
  )
}

