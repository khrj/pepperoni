import * as React from "react"
import { ChevronLeft, ChevronRight, MoreHorizontal } from "lucide-react"

import { cn } from "@/lib/utils"
import { ButtonProps, buttonVariants } from "@/components/ui/button"

// Type definitions
type PaginationProps = React.ComponentProps<"nav"> & {
	className?: string
}

type PaginationContentProps = React.ComponentProps<"ul"> & {
	className?: string
}

type PaginationItemProps = React.ComponentProps<"li"> & {
	className?: string
}

type PaginationLinkProps = {
	isActive?: boolean
	size?: Pick<ButtonProps, "size">["size"]
	className?: string
} & React.ComponentProps<"a">

type DynamicPaginationItemsProps = {
	currentPage: number
	totalPages: number
	setCurrentPage: (page: number) => void
}
const DynamicPaginationItems: React.FC<DynamicPaginationItemsProps> = ({ currentPage, totalPages, setCurrentPage }) => {
	// Always show first page, last page, current page, and siblings
	const siblingCount = 1
	const showPages: JSX.Element[] = []
	const addedPages = new Set<number>() // Track which pages have been added

	// Helper to add page numbers
	const addPageItem = (pageNum: number): void => {
		if (addedPages.has(pageNum)) return // Skip if already added

		addedPages.add(pageNum)
		showPages.push(
			<PaginationItem key={pageNum}>
				<PaginationLink isActive={currentPage === pageNum} onClick={() => setCurrentPage(pageNum)}>
					{pageNum}
				</PaginationLink>
			</PaginationItem>
		)
	}

	// Helper to add ellipsis
	const addEllipsis = (key: string): void => {
		showPages.push(
			<PaginationItem key={`ellipsis-${key}`}>
				<PaginationEllipsis />
			</PaginationItem>
		)
	}

	// Special case for very few pages
	if (totalPages <= 5) {
		// Show all pages without ellipses
		for (let i = 1; i <= totalPages; i++) {
			addPageItem(i)
		}
		return <>{showPages}</>
	}

	// Always include page 1
	addPageItem(1)

	// Calculate range around current page
	const leftSibling = Math.max(currentPage - siblingCount, 2)
	const rightSibling = Math.min(currentPage + siblingCount, totalPages - 1)

	// Determine if we need ellipses
	const shouldShowLeftEllipsis = leftSibling > 2
	const shouldShowRightEllipsis = rightSibling < totalPages - 1

	// Add left ellipsis or page 2
	if (shouldShowLeftEllipsis) {
		addEllipsis("left")
	} else if (leftSibling === 2) {
		addPageItem(2)
	}

	// Add range around current page
	for (let i = leftSibling; i <= rightSibling; i++) {
		addPageItem(i)
	}

	// Add right ellipsis or second-to-last page
	if (shouldShowRightEllipsis) {
		addEllipsis("right")
	} else if (rightSibling === totalPages - 1) {
		addPageItem(totalPages - 1)
	}

	// Always include last page (if not already added)
	addPageItem(totalPages)

	return <>{showPages}</>
}

// Base Pagination Components
const Pagination = React.forwardRef<HTMLElement, PaginationProps>(({ className, ...props }, ref) => (
	<nav
		ref={ref}
		role="navigation"
		aria-label="pagination"
		className={cn("mx-auto flex w-full justify-center", className)}
		{...props}
	/>
))

const PaginationContent = React.forwardRef<HTMLUListElement, PaginationContentProps>(({ className, ...props }, ref) => (
	<ul ref={ref} className={cn("flex flex-row items-center gap-1", className)} {...props} />
))

const PaginationItem = React.forwardRef<HTMLLIElement, PaginationItemProps>(({ className, ...props }, ref) => (
	<li ref={ref} className={cn("", className)} {...props} />
))

const PaginationLink: React.FC<PaginationLinkProps> = ({ className, isActive, size = "icon", ...props }) => (
	<a
		aria-current={isActive ? "page" : undefined}
		className={cn(
			buttonVariants({
				variant: isActive ? "outline" : "ghost",
				size,
			}),
			className
		)}
		{...props}
	/>
)

const PaginationPrevious: React.FC<React.ComponentProps<typeof PaginationLink>> = ({ className, ...props }) => (
	<PaginationLink
		aria-label="Go to previous page"
		size="default"
		className={cn("gap-1 pl-2.5", className)}
		{...props}
	>
		<ChevronLeft className="h-4 w-4" />
		<span>Previous</span>
	</PaginationLink>
)

const PaginationNext: React.FC<React.ComponentProps<typeof PaginationLink>> = ({ className, ...props }) => (
	<PaginationLink aria-label="Go to next page" size="default" className={cn("gap-1 pr-2.5", className)} {...props}>
		<span>Next</span>
		<ChevronRight className="h-4 w-4" />
	</PaginationLink>
)

const PaginationEllipsis: React.FC<React.ComponentProps<"span"> & { className?: string }> = ({
	className,
	...props
}) => (
	<span aria-hidden className={cn("flex h-9 w-9 items-center justify-center", className)} {...props}>
		<MoreHorizontal className="h-4 w-4" />
		<span className="sr-only">More pages</span>
	</span>
)

// For display names
Pagination.displayName = "Pagination"
PaginationContent.displayName = "PaginationContent"
PaginationItem.displayName = "PaginationItem"
PaginationLink.displayName = "PaginationLink"
PaginationPrevious.displayName = "PaginationPrevious"
PaginationNext.displayName = "PaginationNext"
PaginationEllipsis.displayName = "PaginationEllipsis"

export {
	Pagination,
	PaginationContent,
	PaginationEllipsis,
	PaginationItem,
	PaginationLink,
	PaginationNext,
	PaginationPrevious,
	DynamicPaginationItems,
}
