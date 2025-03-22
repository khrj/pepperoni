"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Clock, FileUp, LayoutDashboard, LineChart, Menu, Moon, Sun } from "lucide-react"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"

export default function ClientLayout({ children }: { children: React.ReactNode }) {
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = useState(false)

  // Avoid hydration mismatch
  useEffect(() => {
    setMounted(true)
  }, [])

  return (
    <SidebarProvider>
      <div className="flex min-h-screen">
        <Sidebar className="border-r">
          <SidebarHeader className="flex items-center px-4 py-2">
            <div className="flex items-center gap-2">
              <Clock className="h-6 w-6" />
              <span className="text-lg font-bold">Pepperoni</span>
            </div>
          </SidebarHeader>
          <SidebarContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <a href="/">
                    <FileUp className="h-4 w-4" />
                    <span>Upload</span>
                  </a>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <a href="/dashboard">
                    <LayoutDashboard className="h-4 w-4" />
                    <span>Dashboard</span>
                  </a>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <a href="/packets">
                    <LineChart className="h-4 w-4" />
                    <span>Packet Details</span>
                  </a>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <a href="/insights">
                    <LineChart className="h-4 w-4" />
                    <span>Insights</span>
                  </a>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarContent>
          <SidebarFooter className="p-4">
            {mounted && (
              <Button variant="outline" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                <span className="sr-only">Toggle theme</span>
              </Button>
            )}
          </SidebarFooter>
        </Sidebar>
        <div className="flex-1 overflow-auto">
          <header className="flex h-14 items-center gap-4 border-b bg-background px-6">
            <SidebarTrigger className="lg:hidden">
              <Menu className="h-6 w-6" />
              <span className="sr-only">Toggle Menu</span>
            </SidebarTrigger>
            <div className="flex-1" />
            <Button variant="outline" size="sm">
              Export Report
            </Button>
          </header>
          <main className="container mx-auto py-6">{children}</main>
        </div>
      </div>
    </SidebarProvider>
  )
}

