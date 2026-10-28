import type { ButtonHTMLAttributes } from 'react'

type Variant = 'default' | 'primary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  small?: boolean
  /** Icon-only button (no visible label) — pairs with `.btn-icon` sizing, always pass a
   * `title` alongside this so the button stays discoverable (see round-11 audit: several
   * icon-only buttons in the mockup shipped without one and were effectively invisible). */
  iconOnly?: boolean
}

const VARIANT_CLASS: Record<Variant, string> = {
  default: '',
  primary: 'btn-primary',
  ghost: 'btn-ghost',
  danger: 'btn-danger',
}

export function Button({ variant = 'default', small, iconOnly, className, title, children, ...rest }: ButtonProps) {
  if (iconOnly && !title && import.meta.env.DEV) {
    console.warn('<Button iconOnly> without a title is not discoverable — see round-11 design audit')
  }
  const classes = ['btn', VARIANT_CLASS[variant], small ? 'btn-sm' : '', iconOnly ? 'btn-icon' : '', className]
    .filter(Boolean)
    .join(' ')
  return (
    <button className={classes} title={title} {...rest}>
      {children}
    </button>
  )
}
