"use client"

import * as React from "react"
import { ThemeProvider as NextThemesProvider } from "next-themes"
import type { ThemeProviderProps } from "next-themes"

export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>
}

export function useTheme() {
  const { theme, setTheme } = React.useContext(
    // @ts-ignore - next-themes doesn't export its context type
    React.createContext({
      theme: undefined,
      setTheme: (theme: string) => {},
    }),
  )

  return { theme, setTheme }
}

