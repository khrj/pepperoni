"use client"

import { useTheme as useNextTheme } from "next-themes"

export function useTheme() {
  const { theme, setTheme } = useNextTheme()
  return { theme, setTheme }
}

