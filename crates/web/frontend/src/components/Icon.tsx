/**
 * Icon sprite — ported verbatim from the signed-off design artifact. `<use href="#ic-x">`
 * only resolves against `<symbol>` definitions in the *same* document, so this has to be
 * rendered inline in the DOM (once, near the app root) rather than loaded as an external
 * asset — hence `dangerouslySetInnerHTML` here: the content is a fixed, build-authored
 * string with no user input in it, so there's no injection surface, and hand-converting
 * 46 SVG symbols' attributes to JSX camelCase would be pure transcription risk for no
 * benefit.
 */
const ICON_SPRITE = `<defs>
  <symbol id="ic-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.2"/><rect x="14" y="3" width="7" height="7" rx="1.2"/><rect x="3" y="14" width="7" height="7" rx="1.2"/><rect x="14" y="14" width="7" height="7" rx="1.2"/></symbol>
  <symbol id="ic-router" viewBox="0 0 24 24"><rect x="3" y="10" width="18" height="8" rx="1.5"/><path d="M7 10V7a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v3M7 14h.01M11 14h.01"/></symbol>
  <symbol id="ic-bell" viewBox="0 0 24 24"><path d="M6 9a6 6 0 0 1 12 0c0 4 1.5 5.5 1.5 5.5H4.5S6 13 6 9Z"/><path d="M10 19a2 2 0 0 0 4 0"/></symbol>
  <symbol id="ic-stack" viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/></symbol>
  <symbol id="ic-terminal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></symbol>
  <symbol id="ic-sliders" viewBox="0 0 24 24"><path d="M5 21V13M5 9V3M12 21v-4M12 13V3M19 21v-8M19 9V3"/><circle cx="5" cy="11" r="2"/><circle cx="12" cy="15" r="2"/><circle cx="19" cy="11" r="2"/></symbol>
  <symbol id="ic-radar" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18 7"/><circle cx="12" cy="12" r="1" class="ic-fill"/></symbol>
  <symbol id="ic-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 0 1-4 0v-.09a1.7 1.7 0 0 0-1-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 0 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06A2 2 0 1 1 7.03 4.24l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.55V3a2 2 0 0 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.55 1H21a2 2 0 0 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1Z"/></symbol>
  <symbol id="ic-users" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><path d="M3.5 20c.6-3.3 3-5 5.5-5s4.9 1.7 5.5 5"/><circle cx="17" cy="9" r="2.4"/><path d="M15.7 15.2c2 .3 3.6 1.8 4 4.5"/></symbol>
  <symbol id="ic-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></symbol>
  <symbol id="ic-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
  <symbol id="ic-refresh" viewBox="0 0 24 24"><path d="M3 12a9 9 0 0 1 15.3-6.4L21 8M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15.3 6.4L3 16M3 21v-5h5"/></symbol>
  <symbol id="ic-pause" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></symbol>
  <symbol id="ic-play" viewBox="0 0 24 24"><path d="M7 4.5v15l13-7.5-13-7.5Z"/></symbol>
  <symbol id="ic-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2m2 0-1 13a2 2 0 0 1-2 2H10a2 2 0 0 1-2-2L7 7"/></symbol>
  <symbol id="ic-pencil" viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5Z"/></symbol>
  <symbol id="ic-chevron-down" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></symbol>
  <symbol id="ic-chevron-right" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></symbol>
  <symbol id="ic-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
  <symbol id="ic-check" viewBox="0 0 24 24"><path d="m5 13 4 4L19 7"/></symbol>
  <symbol id="ic-external" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4 10 14M8 6H5a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3"/></symbol>
  <symbol id="ic-comment" viewBox="0 0 24 24"><path d="M4 5h16v11H8l-4 4V5Z"/></symbol>
  <symbol id="ic-filter" viewBox="0 0 24 24"><path d="M4 5h16l-6 8v6l-4 2v-8L4 5Z"/></symbol>
  <symbol id="ic-sort" viewBox="0 0 24 24"><path d="M7 4v16M4 7l3-3 3 3M17 20V4M14 17l3 3 3-3"/></symbol>
  <symbol id="ic-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
  <symbol id="ic-moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"/></symbol>
  <symbol id="ic-more" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.3" class="ic-fill"/><circle cx="12" cy="12" r="1.3" class="ic-fill"/><circle cx="19" cy="12" r="1.3" class="ic-fill"/></symbol>
  <symbol id="ic-dot" viewBox="0 0 24 24"><circle cx="12" cy="12" r="6" class="ic-fill"/></symbol>
  <symbol id="ic-triangle" viewBox="0 0 24 24"><path d="M12 4 22 20H2L12 4Z"/><path d="M12 10v4M12 17h.01"/></symbol>
  <symbol id="ic-check-circle" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.5 2.5L16 9.5"/></symbol>
  <symbol id="ic-x-circle" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></symbol>
  <symbol id="ic-wifi" viewBox="0 0 24 24"><path d="M2 8.5a16 16 0 0 1 20 0M5.5 12a11 11 0 0 1 13 0M9 15.5a6 6 0 0 1 6 0"/><circle cx="12" cy="19" r="1" class="ic-fill"/></symbol>
  <symbol id="ic-lock" viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></symbol>
  <symbol id="ic-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></symbol>
  <symbol id="ic-arrow-right" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></symbol>
  <symbol id="ic-menu" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
  <symbol id="ic-logout" viewBox="0 0 24 24"><path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3M16 17l5-5-5-5M21 12H9"/></symbol>
  <symbol id="ic-grip" viewBox="0 0 24 24"><circle cx="9" cy="6" r="1.3" class="ic-fill"/><circle cx="15" cy="6" r="1.3" class="ic-fill"/><circle cx="9" cy="12" r="1.3" class="ic-fill"/><circle cx="15" cy="12" r="1.3" class="ic-fill"/><circle cx="9" cy="18" r="1.3" class="ic-fill"/><circle cx="15" cy="18" r="1.3" class="ic-fill"/></symbol>
  <symbol id="ic-arrow-up" viewBox="0 0 24 24"><path d="M12 19V5M6 11l6-6 6 6"/></symbol>
  <symbol id="ic-arrow-down" viewBox="0 0 24 24"><path d="M12 5v14M18 13l-6 6-6-6"/></symbol>
  <symbol id="ic-layout" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 9v12"/></symbol>
  <symbol id="ic-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/></symbol>
  <symbol id="ic-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="1.5"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></symbol>
  <symbol id="ic-download" viewBox="0 0 24 24"><path d="M12 3v12m0 0 4.5-4.5M12 15 7.5 10.5"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></symbol>
  <symbol id="ic-history" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v4h4"/><path d="M12 8v4l3 2"/></symbol>
  <symbol id="ic-command" viewBox="0 0 24 24"><path d="M8 3a2.5 2.5 0 0 1 2.5 2.5V8h-5V5.5A2.5 2.5 0 0 1 8 3ZM16 3a2.5 2.5 0 0 0-2.5 2.5V8h5V5.5A2.5 2.5 0 0 0 16 3ZM8 21a2.5 2.5 0 0 0 2.5-2.5V16h-5v2.5A2.5 2.5 0 0 0 8 21ZM16 21a2.5 2.5 0 0 1-2.5-2.5V16h5v2.5a2.5 2.5 0 0 1-2.5 2.5Z"/><rect x="8" y="8" width="8" height="8"/></symbol>
  <symbol id="ic-paperclip" viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></symbol>
  <symbol id="ic-mail" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></symbol>
</defs>`

/** Icon names available in the sprite — kept as a union so `<Icon name="..."/>` gets
 * autocomplete/typo-checking instead of accepting an arbitrary string. */
export type IconName =
  | 'grid' | 'router' | 'bell' | 'stack' | 'terminal' | 'sliders' | 'radar' | 'gear'
  | 'users' | 'search' | 'plus' | 'refresh' | 'pause' | 'play' | 'trash' | 'pencil'
  | 'chevron-down' | 'chevron-right' | 'x' | 'check' | 'external' | 'comment' | 'filter'
  | 'sort' | 'sun' | 'moon' | 'more' | 'dot' | 'triangle' | 'check-circle' | 'x-circle'
  | 'wifi' | 'lock' | 'clock' | 'arrow-right' | 'menu' | 'logout' | 'grip' | 'arrow-up'
  | 'arrow-down' | 'layout' | 'key' | 'copy' | 'download' | 'history' | 'command' | 'paperclip' | 'mail'

/** Renders the sprite's `<symbol>` defs once — mount near the app root, before any
 * `<Icon>` usage. Invisible (`display:none` via `.icon-sprite`), just a definition pool. */
export function IconSprite() {
  return (
    <svg className="icon-sprite" aria-hidden="true" style={{ display: 'none' }} dangerouslySetInnerHTML={{ __html: ICON_SPRITE }} />
  )
}

/** A single icon — `<Icon name="trash" />`. `className` merges with the base `.ic` class
 * (stroke/fill come from CSS, see global.css) so callers can add sizing/color overrides
 * the same way the design artifact did (e.g. `.metric-name-btn .ic`). */
export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `ic ${className}` : 'ic'} aria-hidden="true">
      <use href={`#ic-${name}`} />
    </svg>
  )
}
