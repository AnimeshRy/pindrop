import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Merge Tailwind class names with later overrides winning. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
