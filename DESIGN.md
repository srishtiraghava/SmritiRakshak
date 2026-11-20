---
name: SmritiRakshak
description: Evidence-first memory security for AI agent developers.
colors:
  canvas: "#e9efe9"
  shell: "#e5ece5"
  surface: "#f4f6f2"
  surface-raised: "#edf2ed"
  surface-hover: "#dfe9e0"
  line: "#cbd7cc"
  line-strong: "#9eafa2"
  ink: "#293d34"
  muted: "#4d6358"
  quiet: "#74877a"
  emerald: "#293f35"
  emerald-deep: "#d6e3d7"
  cyan: "#467f81"
  success: "#3e704f"
  warning: "#94661c"
  danger: "#a64d44"
  info: "#467f81"
typography:
  headline:
    fontFamily: "system-ui, Segoe UI, sans-serif"
    fontSize: "clamp(21px, 2vw, 27px)"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  body:
    fontFamily: "system-ui, Segoe UI, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "system-ui, Segoe UI, sans-serif"
    fontSize: "11px"
    fontWeight: 550
  data:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "11px"
    fontWeight: 400
rounded:
  control: "8px"
  panel: "12px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.emerald}"
    textColor: "#f4f6f2"
    rounded: "{rounded.control}"
    padding: "0 14px"
    height: "40px"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 14px"
    height: "40px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "20px"
  field:
    backgroundColor: "#f7f8f5"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "9px 11px"
    height: "40px"
  status-success:
    backgroundColor: "#e1eee4"
    textColor: "{colors.success}"
    rounded: "6px"
    padding: "2px 8px"
---

## Overview

**Creative North Star: The Roll - Evidence docket.** SmritiRakshak is an operational workspace for developers building AI agents. Each memory is treated as an evidence record: its risk score, detector findings, and current disposition resolve into one legible decision spine. The first view moves from live service health to real stored decisions and the workflows that need attention.

Soft sage grounds the workspace, warm near-white surfaces hold evidence, and deep forest green anchors primary actions and trusted states. Muted teal carries secondary emphasis and keyboard focus. Fine rules, compact controls, and measured spacing keep evidence scannable without turning the screen into a wall of panels.

### Key Characteristics

- A consistent risk, findings, and disposition hierarchy wherever a memory is inspected.
- Data comes from live API responses; status and empty states remain explicit.
- System sans is used for prose; tabular numerals and monospace are reserved for measurements and identifiers.

## Colors

### Primary
- **Forest Green** (#293F35): primary actions, selected emphasis, and trusted actions.

### Secondary
- **Muted Teal** (#467F81): secondary highlights, links, and visible keyboard focus.
- **Pale Forest Sage** (#D6E3D7): selected navigation and soft positive-state surface.

### Tertiary
- **Amber Signal** (#94661C): review and warning states.
- **Warm Coral** (#A64D44): danger, blocked, and destructive states.

### Neutral
- **Soft Sage Canvas** (#E9EFE9): application ground.
- **Sage Shell** (#E5ECE5): header and navigation surface.
- **Warm Near-White** (#F4F6F2): panels, tables, and contained work areas.
- **Raised Sage Surface** (#EDF2ED): raised content surface.
- **Sage Hover** (#DFE9E0): interactive hover surface.
- **Moss Ink** (#293D34): primary text.
- **Muted Moss** (#4D6358): secondary text.
- **Quiet Sage** (#74877A): subdued metadata and placeholder text.
- **Sage Rule** (#CBD7CC): dividers and default borders.
- **Strong Sage Rule** (#9EAFA2): controls and higher-emphasis outlines.
- **Trusted Green** (#3E704F): success state.

**The Named-State Rule.** Amber and coral communicate review or danger; never use them as decoration. Every colored state also has a readable label.

## Typography

**Display Font:** System UI with Segoe UI and sans-serif fallbacks.
**Body Font:** System UI with Segoe UI and sans-serif fallbacks.
**Label/Mono Font:** UI monospace, SFMono-Regular, Consolas, monospace for identifiers and values.

**Character:** Compact, neutral sans-serif keeps controls and evidence easy to scan. Tabular numerals make counts and scores align; monospace marks technical data rather than styling ordinary prose.

### Hierarchy
- **Headline** (650, responsive 21-27px, 1.2 line height): page titles.
- **Title** (630, 14px): panel and evidence section headings.
- **Body** (400, 14px, 1.5 line height): copy and explanations.
- **Label** (550-700, 10-12px): control labels, table headings, and state chips.
- **Data** (400, 11px): IDs and technical identifiers; score values use tabular numerals.

**The Evidence-First Type Rule.** Keep prose in the system sans; use monospace only for code, IDs, hashes, timestamps, and measured values.

## Layout

The desktop shell uses a sticky status header above a fixed-width navigation rail and a min-width-safe main work area. Page content uses a flexible grid with 18px gaps; chart columns collapse to one column at narrower widths. Panels use 20px inner padding, reduced to 16px on mobile. At widths of 720px and below, navigation becomes a slide-in menu and page actions stack; at 430px and below, small controls and metadata tighten further. Tables scroll inside their own frames so the page itself stays within the viewport. The document supports a 320px minimum viewport width.

## Elevation & Depth

Depth comes primarily from tonal layers and fine borders, not shadows. The modal is the exception: it uses a soft forest-tinted shadow (`0 24px 64px rgb(31 55 43 / 22%)`) to separate the focused task from the workspace. Hover motion is brief and restrained; reduced-motion preferences suppress transitions and animation.

## Shapes

Controls use gently rounded corners (8px); panels and table frames use a slightly broader radius (12px). Compact status chips use 6px corners. Borders are full and quiet, with stronger strokes for controls; avoid glow, pure black, and decorative gradients.

## Components

### Buttons
- **Shape:** Compact rounded controls (8px), at least 40px high, with 14px horizontal padding.
- **Primary:** Forest green fill with near-white text; use for the main task.
- **Secondary:** Near-white surface, moss text, and strong sage border.
- **Danger:** Dark red-tinted fill with pale text for destructive actions.
- **Hover / Focus:** Slight lift and surface shift on hover; clear 2px teal focus outline with a 3px offset.
- **Disabled:** Lower opacity, no lift, and a disabled cursor.

### Chips
- **Style:** Compact, labeled badges with a tinted semantic background, readable text, and a full border.
- **State:** Allow, flag, quarantine, block, low, medium, high, critical, and unknown states have distinct tones. Unknown values stay neutral.

### Cards / Containers
- **Corner Style:** 12px radius.
- **Background:** Warm near-white surface with a fine sage rule border.
- **Shadow Strategy:** Flat by default; modal shadow is reserved for interruption and focus.
- **Internal Padding:** 20px desktop, 16px mobile.

### Inputs / Fields
- **Style:** Soft near-white inset surface, strong sage border, 8px radius, and 40px minimum height.
- **Focus:** Muted teal border and low-opacity teal outline.
- **Error / Disabled:** Error notices use coral state colors; disabled controls reduce opacity and stop hover lift.

### Navigation
- **Style:** Named six-item rail with moss text and a pale sage active surface. At mobile width it becomes an overlay drawer with a backdrop and menu toggle; Escape closes the drawer.

### Decision Spine
Risk score, severity, and current decision share a consistent sequence in memory details. Detector evidence remains visually distinct from disposition, preserving the relationship without implying unrecorded history.

## Do's and Don'ts

### Do:
- **Do** keep memory risk, findings, and disposition together when inspecting a record.
- **Do** use live service responses and show explicit loading, error, empty, and disabled states.
- **Do** reserve forest green, teal, amber, and coral for their defined functional roles.
- **Do** keep a visible keyboard focus outline and support reduced motion.

### Don't:
- **Don't** use oversized metric cards or decorative threat charts in place of evidence.
- **Don't** communicate a security state by color alone.
- **Don't** apply monospace to ordinary prose or use glow, pure-black surfaces, or decorative gradients.
