/**
 * @module engines/frontend-engine
 * Frontend Design & Styling Engine (krusch-frontend-mcp) for KruschStack.
 * Provides deterministic color harmony & WCAG 2.1 contrast math, CSS-to-Tailwind compilation,
 * design rule queries, canonical HTML/SVG templates, and responsive breakpoint specs.
 */

import { okEnvelope } from '../db/sqlite.js';

const DEFAULT_DESIGN_RULES = [
  {
    rule_id: 'RULE-COLOR-01',
    category: 'color',
    title: 'High-Contrast Cyber Surface Hierarchy',
    guidance: 'Pair deep obsidian surfaces (#0a0e17) with electric cyan accents (#00e5ff) and maintain WCAG AA (>= 4.5:1) contrast for body copy.',
    tokens: { bgPrimary: '#0a0e17', bgSurface: '#111827', accentCyan: '#00e5ff', textPrimary: '#f8fafc' }
  },
  {
    rule_id: 'RULE-TYPE-01',
    category: 'typography',
    title: 'Technical Monospace & Geometric Sans Pairing',
    guidance: 'Use Space Grotesk or Inter for structural headings and JetBrains Mono for telemetry, hashes, and CLI snippets.',
    tokens: { fontSans: 'Inter, system-ui, sans-serif', fontMono: 'JetBrains Mono, monospace' }
  },
  {
    rule_id: 'RULE-LAYOUT-01',
    category: 'layout',
    title: 'Responsive Bento Grid & 8px Spacing Cadence',
    guidance: 'Align container padding and grid gaps on an 8px (0.5rem) spatial cadence across 375px, 768px, and 1440px breakpoints.',
    tokens: { gapMobile: '0.75rem', gapTablet: '1rem', gapDesktop: '1.5rem', maxWidth: '80rem' }
  },
  {
    rule_id: 'RULE-A11Y-01',
    category: 'accessibility',
    title: 'WCAG 2.1 Focus Ring & Semantic Landmarks',
    guidance: 'All interactive controls require visible focus-visible outlines (2px solid #00e5ff) and semantic landmark regions.',
    tokens: { focusRing: '0 0 0 2px #00e5ff', minTouchTarget: '44px' }
  },
  {
    rule_id: 'RULE-COMP-01',
    category: 'components',
    title: 'Deadbolt Verification Footer & Telemetry Badges',
    guidance: 'Include deterministic status badges and the canonical deadbolt SVG seal in technical article shells.',
    tokens: { borderSubtle: 'rgba(0, 229, 255, 0.22)', radiusCard: '0.75rem' }
  }
];

const CANONICAL_TEMPLATES = {
  'article-shell': {
    template_id: 'article-shell',
    title: 'Technical Article Shell',
    category: 'layout',
    description: 'Canonical technical article layout with header telemetry bar, prose container, and verification slot.',
    html: `<article class="min-h-screen bg-[#0a0e17] text-slate-100 px-4 py-8 md:px-8 lg:px-16">
  <header class="max-w-4xl mx-auto border-b border-cyan-500/20 pb-6 mb-8">
    <div class="text-xs font-mono uppercase tracking-widest text-cyan-400">KruschStack Technical Brief</div>
    <h1 class="text-3xl md:text-5xl font-bold tracking-tight mt-2">{{TITLE}}</h1>
  </header>
  <main class="max-w-4xl mx-auto prose prose-invert">{{CONTENT}}</main>
</article>`,
    css: '.article-shell { background-color: #0a0e17; color: #f8fafc; }'
  },
  'footer-deadbolt': {
    template_id: 'footer-deadbolt',
    title: 'Footer Deadbolt Seal',
    category: 'navigation',
    description: 'Cryptographic-style verification footer with deadbolt SVG indicator and build metadata.',
    html: `<footer class="border-t border-cyan-500/20 bg-[#070a12] py-6 px-4 text-xs font-mono text-slate-400">
  <div class="max-w-6xl mx-auto flex items-center justify-between gap-4">
    <span class="flex items-center gap-2 text-cyan-400">DEADBOLT VERIFIED // INV-STACK-02</span>
    <span>KruschStack v1.0.0</span>
  </div>
</footer>`,
    css: '.footer-deadbolt { border-top: 1px solid rgba(0, 229, 255, 0.2); }'
  },
  'cyber-grid': {
    template_id: 'cyber-grid',
    title: 'Cyber Grid Background Surface',
    category: 'surface',
    description: 'Subtle radial + orthogonal grid backdrop for technical dashboards and telemetry views.',
    html: `<section class="relative overflow-hidden rounded-xl border border-cyan-500/25 bg-[#0a0e17] p-6">
  <div class="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(0,229,255,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,229,255,0.06)_1px,transparent_1px)] bg-[size:24px_24px]"></div>
  <div class="relative z-10">{{SLOT}}</div>
</section>`,
    css: '.cyber-grid { background-size: 24px 24px; }'
  },
  'deadbolt-svg': {
    template_id: 'deadbolt-svg',
    title: 'Deadbolt Interlock Vector Icon',
    category: 'icon',
    description: 'Canonical inline SVG deadbolt emblem for zero-trust verification badges.',
    html: `<svg class="w-5 h-5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-label="Deadbolt Verified">
  <rect x="4" y="11" width="16" height="9" rx="2" />
  <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  <circle cx="12" cy="15.5" r="1.5" />
</svg>`,
    css: '.deadbolt-svg { stroke: #00e5ff; }'
  },
  'nav-back': {
    template_id: 'nav-back',
    title: 'Breadcrumb Return Navigation Bar',
    category: 'navigation',
    description: 'Accessible top return navigation bar with keyboard shortcut hint.',
    html: `<nav aria-label="Breadcrumb" class="py-3 px-4 border-b border-slate-800 bg-[#0a0e17]/90 backdrop-blur">
  <a href="{{HREF}}" class="inline-flex items-center gap-2 text-sm font-mono text-cyan-400 hover:text-cyan-300">
    <span aria-hidden="true">&larr;</span>
    <span>{{LABEL}}</span>
  </a>
</nav>`,
    css: '.nav-back { backdrop-filter: blur(8px); }'
  }
};

/**
 * Parse a 3- or 6-digit hex color string into { r, g, b }.
 * @param {string} hex
 * @returns {{ r: number, g: number, b: number, hex: string }}
 */
function parseHexColor(hex = '#00e5ff') {
  let clean = String(hex || '#00e5ff').trim().replace(/^#/, '');
  if (/^[0-9a-fA-F]{3}$/.test(clean)) {
    clean = clean
      .split('')
      .map((c) => c + c)
      .join('');
  }
  if (!/^[0-9a-fA-F]{6}$/.test(clean)) {
    clean = '00e5ff';
  }
  const num = parseInt(clean, 16);
  return {
    r: (num >> 16) & 255,
    g: (num >> 8) & 255,
    b: num & 255,
    hex: `#${clean.toLowerCase()}`
  };
}

/**
 * Convert RGB (0-255) to HSL (h: 0-360, s: 0-100, l: 0-100).
 */
function rgbToHsl(r, g, b) {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;

  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case rn:
        h = (gn - bn) / d + (gn < bn ? 6 : 0);
        break;
      case gn:
        h = (bn - rn) / d + 2;
        break;
      default:
        h = (rn - gn) / d + 4;
        break;
    }
    h /= 6;
  }

  return {
    h: Math.round(h * 360),
    s: Math.round(s * 100),
    l: Math.round(l * 100)
  };
}

/**
 * Convert HSL (h: 0-360, s: 0-100, l: 0-100) to { r, g, b, hex }.
 */
function hslToRgb(h, s, l) {
  const hn = (((h % 360) + 360) % 360) / 360;
  const sn = Math.max(0, Math.min(100, s)) / 100;
  const ln = Math.max(0, Math.min(100, l)) / 100;

  let r;
  let g;
  let b;

  if (sn === 0) {
    r = ln;
    g = ln;
    b = ln;
  } else {
    const hue2rgb = (p, q, t) => {
      let tt = t;
      if (tt < 0) tt += 1;
      if (tt > 1) tt -= 1;
      if (tt < 1 / 6) return p + (q - p) * 6 * tt;
      if (tt < 1 / 2) return q;
      if (tt < 2 / 3) return p + (q - p) * (2 / 3 - tt) * 6;
      return p;
    };
    const q = ln < 0.5 ? ln * (1 + sn) : ln + sn - ln * sn;
    const p = 2 * ln - q;
    r = hue2rgb(p, q, hn + 1 / 3);
    g = hue2rgb(p, q, hn);
    b = hue2rgb(p, q, hn - 1 / 3);
  }

  const ri = Math.round(r * 255);
  const gi = Math.round(g * 255);
  const bi = Math.round(b * 255);
  const hex = `#${[ri, gi, bi].map((v) => v.toString(16).padStart(2, '0')).join('')}`;
  return { r: ri, g: gi, b: bi, hex };
}

/**
 * Compute WCAG 2.1 relative luminance for { r, g, b }.
 */
function relativeLuminance({ r, g, b }) {
  const transform = (channel) => {
    const c = channel / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const R = transform(r);
  const G = transform(g);
  const B = transform(b);
  return Number((0.2126 * R + 0.7152 * G + 0.0722 * B).toFixed(4));
}

/**
 * Compute WCAG 2.1 contrast ratio between two RGB colors.
 */
function contrastRatio(rgbA, rgbB) {
  const lumA = relativeLuminance(rgbA);
  const lumB = relativeLuminance(rgbB);
  const brightest = Math.max(lumA, lumB);
  const darkest = Math.min(lumA, lumB);
  return Number(((brightest + 0.05) / (darkest + 0.05)).toFixed(2));
}

const SPACING_PX_MAP = {
  '0': '0',
  '0px': '0',
  '2px': '0.5',
  '4px': '1',
  '0.25rem': '1',
  '6px': '1.5',
  '8px': '2',
  '0.5rem': '2',
  '12px': '3',
  '0.75rem': '3',
  '16px': '4',
  '1rem': '4',
  '20px': '5',
  '1.25rem': '5',
  '24px': '6',
  '1.5rem': '6',
  '32px': '8',
  '2rem': '8',
  '40px': '10',
  '2.5rem': '10',
  '48px': '12',
  '3rem': '12'
};

/**
 * Convert a single CSS declaration (prop, val) to a Tailwind utility class.
 */
function mapDeclarationToTailwind(prop, val) {
  const p = prop.toLowerCase().trim();
  const v = val.toLowerCase().trim().replace(/!important$/, '').trim();

  if (p === 'display') {
    const map = {
      flex: 'flex',
      'inline-flex': 'inline-flex',
      grid: 'grid',
      'inline-grid': 'inline-grid',
      block: 'block',
      'inline-block': 'inline-block',
      inline: 'inline',
      none: 'hidden'
    };
    return map[v] || null;
  }

  if (p === 'flex-direction') {
    const map = {
      row: 'flex-row',
      'row-reverse': 'flex-row-reverse',
      column: 'flex-col',
      'column-reverse': 'flex-col-reverse'
    };
    return map[v] || null;
  }

  if (p === 'flex-wrap') {
    const map = { wrap: 'flex-wrap', nowrap: 'flex-nowrap', 'wrap-reverse': 'flex-wrap-reverse' };
    return map[v] || null;
  }

  if (p === 'align-items') {
    const map = {
      center: 'items-center',
      'flex-start': 'items-start',
      start: 'items-start',
      'flex-end': 'items-end',
      end: 'items-end',
      stretch: 'items-stretch',
      baseline: 'items-baseline'
    };
    return map[v] || null;
  }

  if (p === 'justify-content') {
    const map = {
      center: 'justify-center',
      'space-between': 'justify-between',
      'space-around': 'justify-around',
      'space-evenly': 'justify-evenly',
      'flex-start': 'justify-start',
      start: 'justify-start',
      'flex-end': 'justify-end',
      end: 'justify-end'
    };
    return map[v] || null;
  }

  if (p === 'padding' || p === 'margin' || p === 'gap') {
    const prefix = p === 'padding' ? 'p' : p === 'margin' ? 'm' : 'gap';
    if (v === 'auto' && prefix === 'm') return 'm-auto';
    if (SPACING_PX_MAP[v]) return `${prefix}-${SPACING_PX_MAP[v]}`;
    return `${prefix}-[${v.replace(/\s+/g, '_')}]`;
  }

  if (p === 'border-radius') {
    const map = {
      '0': 'rounded-none',
      '0px': 'rounded-none',
      '2px': 'rounded-sm',
      '4px': 'rounded',
      '0.25rem': 'rounded',
      '6px': 'rounded-md',
      '0.375rem': 'rounded-md',
      '8px': 'rounded-lg',
      '0.5rem': 'rounded-lg',
      '12px': 'rounded-xl',
      '0.75rem': 'rounded-xl',
      '16px': 'rounded-2xl',
      '1rem': 'rounded-2xl',
      '9999px': 'rounded-full',
      '50%': 'rounded-full'
    };
    return map[v] || `rounded-[${v}]`;
  }

  if (p === 'font-weight') {
    const map = {
      '300': 'font-light',
      light: 'font-light',
      '400': 'font-normal',
      normal: 'font-normal',
      '500': 'font-medium',
      medium: 'font-medium',
      '600': 'font-semibold',
      semibold: 'font-semibold',
      '700': 'font-bold',
      bold: 'font-bold',
      '800': 'font-extrabold'
    };
    return map[v] || null;
  }

  if (p === 'text-align') {
    const map = { left: 'text-left', center: 'text-center', right: 'text-right', justify: 'text-justify' };
    return map[v] || null;
  }

  if (p === 'position') {
    if (['relative', 'absolute', 'fixed', 'sticky', 'static'].includes(v)) return v;
  }

  if (p === 'width') {
    if (v === '100%') return 'w-full';
    if (v === '100vw') return 'w-screen';
    if (v === 'auto') return 'w-auto';
    return `w-[${v}]`;
  }

  if (p === 'height') {
    if (v === '100%') return 'h-full';
    if (v === '100vh') return 'h-screen';
    if (v === 'auto') return 'h-auto';
    return `h-[${v}]`;
  }

  if (p === 'overflow') {
    if (['hidden', 'auto', 'scroll', 'visible'].includes(v)) return `overflow-${v}`;
  }

  if (p === 'cursor') {
    if (v === 'pointer') return 'cursor-pointer';
  }

  return null;
}

/**
 * Create the Frontend Design & Styling Engine.
 * @param {object} [options]
 * @param {import('node:sqlite').DatabaseSync} [options.db]
 */
export function createFrontendEngine({ db } = {}) {
  function ensureDesignRulesSeeded() {
    if (!db) return;
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM frontend_design_rules').get();
    if (row && row.cnt > 0) return;

    const insert = db.prepare(`
      INSERT OR IGNORE INTO frontend_design_rules (rule_id, category, title, guidance, tokens_json)
      VALUES (?, ?, ?, ?, ?)
    `);
    for (const rule of DEFAULT_DESIGN_RULES) {
      insert.run(rule.rule_id, rule.category, rule.title, rule.guidance, JSON.stringify(rule.tokens));
    }
  }

  /**
   * Generate a deterministic 5-stop color palette and WCAG 2.1 contrast profile.
   * @param {object} [params]
   * @param {string} [params.base_hex='#00e5ff']
   * @param {string} [params.harmony='complementary']
   */
  function generateColorPalette({ base_hex = '#00e5ff', harmony = 'complementary' } = {}) {
    const baseRgb = parseHexColor(base_hex);
    const baseHsl = rgbToHsl(baseRgb.r, baseRgb.g, baseRgb.b);
    const darkRef = parseHexColor('#0a0e17');
    const lightRef = parseHexColor('#ffffff');

    const lightnessStops = [
      { stop: 50, l: 92 },
      { stop: 200, l: 75 },
      { stop: 500, l: baseHsl.l || 50 },
      { stop: 700, l: 34 },
      { stop: 900, l: 16 }
    ];

    const palette = lightnessStops.map(({ stop, l }) => {
      const rgb = stop === 500 ? baseRgb : hslToRgb(baseHsl.h, baseHsl.s, l);
      const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
      const lum = relativeLuminance(rgb);
      const cDark = contrastRatio(rgb, darkRef);
      const cLight = contrastRatio(rgb, lightRef);
      return {
        stop,
        hex: rgb.hex,
        rgb: { r: rgb.r, g: rgb.g, b: rgb.b },
        hsl,
        luminance: lum,
        contrast_dark: cDark,
        contrast_light: cLight
      };
    });

    const harmonyOffsets = {
      complementary: [0, 180],
      analogous: [0, 30, 330],
      triadic: [0, 120, 240],
      'split-complementary': [0, 150, 210]
    };
    const offsets = harmonyOffsets[harmony] || harmonyOffsets.complementary;
    const harmonySwatches = offsets.map((offset) => {
      const rgb = hslToRgb((baseHsl.h + offset) % 360, baseHsl.s, baseHsl.l || 50);
      return {
        hue_offset: offset,
        hex: rgb.hex,
        contrast_dark: contrastRatio(rgb, darkRef),
        contrast_light: contrastRatio(rgb, lightRef)
      };
    });

    const baseLum = relativeLuminance(baseRgb);
    const againstDark = contrastRatio(baseRgb, darkRef);
    const againstLight = contrastRatio(baseRgb, lightRef);

    return okEnvelope(
      'generate_color_palette',
      `Generated 5-stop ${harmony} palette for ${baseRgb.hex} (WCAG dark ${againstDark}:1, light ${againstLight}:1)`,
      {
        base_hex: baseRgb.hex,
        harmony,
        rgb: { r: baseRgb.r, g: baseRgb.g, b: baseRgb.b },
        hsl: baseHsl,
        luminance: baseLum,
        wcag: {
          luminance: baseLum,
          against_dark: againstDark,
          against_light: againstLight,
          aa_dark: againstDark >= 4.5,
          aaa_dark: againstDark >= 7.0,
          aa_light: againstLight >= 4.5,
          aaa_light: againstLight >= 7.0
        },
        palette,
        stops: Object.fromEntries(palette.map((p) => [p.stop, p.hex])),
        harmony_swatches: harmonySwatches
      }
    );
  }

  /**
   * Compile raw CSS declarations into deterministic Tailwind utility classes.
   * @param {object} [params]
   * @param {string} [params.css='']
   */
  function cssToTailwind({ css = '' } = {}) {
    const rawCss = String(css || '');
    const stripped = rawCss
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^[^{]*\{/, '')
      .replace(/\}\s*$/, '');

    const declarations = stripped
      .split(';')
      .map((d) => d.trim())
      .filter(Boolean);

    const classes = [];
    const mappings = [];
    const unmapped = [];

    for (const decl of declarations) {
      const colonIdx = decl.indexOf(':');
      if (colonIdx === -1) continue;
      const prop = decl.slice(0, colonIdx).trim();
      const val = decl.slice(colonIdx + 1).trim();
      const tw = mapDeclarationToTailwind(prop, val);
      if (tw) {
        if (!classes.includes(tw)) {
          classes.push(tw);
        }
        mappings.push({ property: prop, value: val, tailwind: tw });
      } else {
        unmapped.push({ property: prop, value: val });
      }
    }

    const className = classes.join(' ');
    return okEnvelope(
      'css_to_tailwind',
      `Compiled ${mappings.length} CSS declaration(s) into Tailwind utilities`,
      {
        classes,
        tailwind_classes: classes,
        className,
        tailwind: className,
        mappings,
        unmapped
      }
    );
  }

  /**
   * Query canonical frontend design rules from SQLite.
   * @param {object} [params]
   * @param {string} [params.query='']
   * @param {string} [params.category]
   */
  function queryDesignRules({ query = '', category } = {}) {
    ensureDesignRulesSeeded();
    const q = String(query || '').trim().toLowerCase();
    const cat = category ? String(category).trim().toLowerCase() : null;

    let rows;
    if (db) {
      rows = db.prepare('SELECT rule_id, category, title, guidance, tokens_json FROM frontend_design_rules ORDER BY id ASC').all();
    } else {
      rows = DEFAULT_DESIGN_RULES.map((r) => ({
        ...r,
        tokens_json: JSON.stringify(r.tokens)
      }));
    }

    const filtered = rows
      .filter((r) => {
        if (cat && cat !== 'all' && r.category.toLowerCase() !== cat) {
          return false;
        }
        if (!q || q === '*') {
          return true;
        }
        const haystack = `${r.rule_id} ${r.category} ${r.title} ${r.guidance}`.toLowerCase();
        return haystack.includes(q);
      })
      .map((r) => ({
        rule_id: r.rule_id,
        category: r.category,
        title: r.title,
        guidance: r.guidance,
        tokens: JSON.parse(r.tokens_json || '{}')
      }));

    return okEnvelope(
      'query_design_rules',
      `Found ${filtered.length} design rule(s)`,
      {
        query: query || '*',
        category: cat || 'all',
        count: filtered.length,
        rules: filtered
      }
    );
  }

  /**
   * Retrieve a canonical HTML/SVG template by template_id.
   * @param {object} [params]
   * @param {string} [params.template_id]
   */
  function getCanonicalTemplate({ template_id } = {}) {
    const id = String(template_id || '').trim();
    const tpl = CANONICAL_TEMPLATES[id];
    if (!tpl) {
      return okEnvelope(
        'get_canonical_template',
        `Unknown canonical template: ${id}`,
        {
          template_id: id,
          available_templates: Object.keys(CANONICAL_TEMPLATES)
        },
        false
      );
    }

    return okEnvelope(
      'get_canonical_template',
      `Loaded canonical template '${tpl.template_id}'`,
      { ...tpl }
    );
  }

  /**
   * List all canonical HTML/SVG templates.
   */
  function listCanonicalTemplates() {
    const templates = Object.values(CANONICAL_TEMPLATES);
    return okEnvelope(
      'list_canonical_templates',
      `Listed ${templates.length} canonical templates`,
      {
        count: templates.length,
        templates
      }
    );
  }

  /**
   * Generate responsive breakpoint specifications for 375px, 768px, and 1440px.
   * @param {object} [params]
   * @param {string} [params.component_type='grid']
   */
  function generateResponsiveBreakpoints({ component_type = 'grid' } = {}) {
    const type = String(component_type || 'grid').toLowerCase().trim();
    const layoutClassesByType = {
      grid: {
        mobile: 'grid grid-cols-1 gap-3 px-4',
        tablet: 'md:grid-cols-2 md:gap-4 md:px-6',
        desktop: 'xl:grid-cols-3 xl:gap-6 xl:px-8 max-w-7xl mx-auto'
      },
      nav: {
        mobile: 'flex flex-col gap-2 px-4 py-3',
        tablet: 'md:flex-row md:items-center md:justify-between md:px-6',
        desktop: 'xl:px-10 max-w-7xl mx-auto'
      },
      hero: {
        mobile: 'flex flex-col gap-4 px-4 py-8 text-left',
        tablet: 'md:py-12 md:px-8',
        desktop: 'xl:flex-row xl:items-center xl:justify-between xl:py-16 max-w-7xl mx-auto'
      }
    };

    const preset = layoutClassesByType[type] || layoutClassesByType.grid;
    const breakpoints = [
      {
        name: 'mobile',
        label: '375px',
        width: 375,
        width_px: '375px',
        columns: 1,
        classes: preset.mobile
      },
      {
        name: 'tablet',
        label: '768px',
        width: 768,
        width_px: '768px',
        columns: type === 'grid' ? 2 : 1,
        classes: preset.tablet
      },
      {
        name: 'desktop',
        label: '1440px',
        width: 1440,
        width_px: '1440px',
        columns: type === 'grid' ? 3 : 2,
        classes: preset.desktop
      }
    ];

    const combinedClasses = `${preset.mobile} ${preset.tablet} ${preset.desktop}`;
    return okEnvelope(
      'generate_responsive_breakpoints',
      `Generated 375px/768px/1440px responsive breakpoints for '${type}'`,
      {
        component_type: type,
        breakpoints,
        specs: {
          '375px': breakpoints[0],
          '768px': breakpoints[1],
          '1440px': breakpoints[2],
          mobile: breakpoints[0],
          tablet: breakpoints[1],
          desktop: breakpoints[2]
        },
        tailwind_classes: combinedClasses
      }
    );
  }

  return {
    generateColorPalette,
    cssToTailwind,
    queryDesignRules,
    getCanonicalTemplate,
    listCanonicalTemplates,
    generateResponsiveBreakpoints
  };
}
