/**
 * Liquid Glass refraction (progressive enhancement)
 *
 * Each glass element gets its own SVG filter used as a `backdrop-filter`.
 * The filter bends the content behind the glass along its rounded-rect bezel
 * the way a thick convex lens would:
 *
 *   - A displacement map is rendered from the element's real size + corner
 *     radius using a signed-distance field. Pixels inside the bezel are pushed
 *     inward with a convex-lens falloff (strong at the rim, zero in the flat
 *     centre), so text in the middle stays crisp and readable.
 *   - Red, green and blue are displaced by slightly different amounts, giving
 *     the faint chromatic dispersion real glass has.
 *   - Frost (blur) and saturation are applied on top.
 *
 * SVG filters inside backdrop-filter only work in Chromium. Everywhere else
 * (Safari, Firefox) this script does nothing and the CSS frosted-blur
 * fallback is used.
 */
(() => {
    const isChromium = !!(navigator.userAgentData &&
        navigator.userAgentData.brands.some(b => /Chromium/i.test(b.brand)));
    if (!isChromium) return;
    if (window.matchMedia('(prefers-reduced-transparency: reduce)').matches) return;

    const SELECTOR = '.glass-panel, .btn-glass, .icon-glass-btn, .chip, .brand-mark';
    const NS = 'http://www.w3.org/2000/svg';

    // Tunables
    const MAX_BEZEL = 26;      // px, width of the refracting rim
    const MAX_DISPLACE = 16;   // px, strongest pixel shift at the very edge
    const DISPERSION = [1, 0.94, 0.88]; // R, G, B displacement multipliers

    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('width', '0');
    svg.setAttribute('height', '0');
    svg.setAttribute('aria-hidden', 'true');
    svg.style.cssText = 'position:absolute;width:0;height:0;pointer-events:none';
    const defs = document.createElementNS(NS, 'defs');
    svg.appendChild(defs);
    document.body.appendChild(svg);

    const state = new WeakMap(); // element -> { id, w, h, r, filter }
    let counter = 0;

    const ro = new ResizeObserver(entries => {
        entries.forEach(e => schedule(e.target));
    });

    const pending = new Set();
    let raf = 0;
    function schedule(el) {
        pending.add(el);
        if (!raf) raf = requestAnimationFrame(flush);
    }
    function flush() {
        raf = 0;
        pending.forEach(update);
        pending.clear();
    }

    function register(el) {
        if (state.has(el)) return;
        state.set(el, { id: 'lg-' + (++counter), w: 0, h: 0, r: 0, filter: null });
        ro.observe(el);
        schedule(el);
    }

    function release(el) {
        const s = state.get(el);
        if (!s) return;
        ro.unobserve(el);
        if (s.filter) s.filter.remove();
        state.delete(el);
    }

    function blurOf(el) {
        // keep the frost strength defined in CSS
        const cs = getComputedStyle(el);
        const bf = cs.backdropFilter || cs.webkitBackdropFilter || '';
        const blur = /blur\([^)]+\)/.exec(bf);
        const sat = /saturate\([^)]+\)/.exec(bf);
        return (blur ? blur[0] : 'blur(16px)') + ' ' + (sat ? sat[0] : 'saturate(180%)');
    }

    function update(el) {
        const s = state.get(el);
        if (!s || !el.isConnected) return;

        const w = Math.round(el.offsetWidth);
        const h = Math.round(el.offsetHeight);
        if (w < 8 || h < 8) return;

        const cs = getComputedStyle(el);
        const radius = Math.min(parseFloat(cs.borderTopLeftRadius) || 0, w / 2, h / 2);

        if (s.filter && s.w === w && s.h === h && s.r === radius) return;
        s.w = w; s.h = h; s.r = radius;

        const bezel = Math.max(2, Math.min(radius, MAX_BEZEL, Math.min(w, h) / 2));
        const maxShift = Math.min(bezel * 0.7, MAX_DISPLACE);
        const mapUrl = buildMap(w, h, radius, bezel);

        if (!s.filter) {
            s.filter = document.createElementNS(NS, 'filter');
            s.filter.setAttribute('id', s.id);
            s.filter.setAttribute('filterUnits', 'userSpaceOnUse');
            s.filter.setAttribute('color-interpolation-filters', 'sRGB');
            defs.appendChild(s.filter);
        }
        s.filter.setAttribute('x', '0');
        s.filter.setAttribute('y', '0');
        s.filter.setAttribute('width', String(w));
        s.filter.setAttribute('height', String(h));

        const scale = maxShift * 2; // map encodes -1..1 around 0.5
        const channel = (idx, matrix) => `
            <feDisplacementMap in="SourceGraphic" in2="map" scale="${(scale * DISPERSION[idx]).toFixed(2)}"
                xChannelSelector="R" yChannelSelector="G" result="d${idx}"/>
            <feColorMatrix in="d${idx}" type="matrix" values="${matrix}" result="c${idx}"/>`;

        s.filter.innerHTML = `
            <feImage href="${mapUrl}" x="0" y="0" width="${w}" height="${h}" preserveAspectRatio="none" result="map"/>
            ${channel(0, '1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0')}
            ${channel(1, '0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0')}
            ${channel(2, '0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0')}
            <feBlend in="c0" in2="c1" mode="screen" result="rg"/>
            <feBlend in="rg" in2="c2" mode="screen"/>`;

        el.style.backdropFilter = `url(#${s.id}) ${blurOf(el)}`;
    }

    /**
     * Displacement map. R = x shift, G = y shift, 128 = no shift.
     * Inside the bezel every pixel is pushed along the inward normal of the
     * rounded rectangle with a convex-lens profile: m = 1 - sqrt(1 - (1-t)^2).
     */
    function buildMap(w, h, r, bezel) {
        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'rgb(128,128,128)';
        ctx.fillRect(0, 0, w, h);

        const img = ctx.getImageData(0, 0, w, h);
        const data = img.data;
        const cx = w / 2, cy = h / 2;
        const bx = cx - r, by = cy - r;

        const px = (x, y) => {
            const dx = x + 0.5 - cx, dy = y + 0.5 - cy;
            const sx = dx < 0 ? -1 : 1, sy = dy < 0 ? -1 : 1;
            const qx = Math.abs(dx) - bx, qy = Math.abs(dy) - by;

            let gx, gy, dist;
            if (qx > 0 && qy > 0) {
                const len = Math.hypot(qx, qy) || 1;
                gx = qx / len; gy = qy / len;
                dist = len - r;
            } else if (qx > qy) {
                gx = 1; gy = 0; dist = qx - r;
            } else {
                gx = 0; gy = 1; dist = qy - r;
            }
            const depth = -dist; // distance inside the edge
            if (depth >= bezel || depth < 0) return;

            const t = depth / bezel;
            const m = 1 - Math.sqrt(1 - (1 - t) * (1 - t));
            // inward normal = -(outward gradient)
            const ox = -gx * sx * m;
            const oy = -gy * sy * m;

            const i = (y * w + x) * 4;
            data[i] = Math.round(128 + ox * 127);
            data[i + 1] = Math.round(128 + oy * 127);
        };

        for (let y = 0; y < h; y++) {
            if (y < bezel || y >= h - bezel) {
                for (let x = 0; x < w; x++) px(x, y);
            } else {
                for (let x = 0; x < bezel; x++) px(x, y);
                for (let x = Math.max(bezel, w - Math.ceil(bezel)); x < w; x++) px(x, y);
            }
        }
        ctx.putImageData(img, 0, 0);
        return canvas.toDataURL('image/png');
    }

    function scan(root) {
        if (root.nodeType !== 1) return;
        if (root.matches(SELECTOR)) register(root);
        root.querySelectorAll(SELECTOR).forEach(register);
    }
    function sweep(root) {
        if (root.nodeType !== 1) return;
        if (state.has(root)) release(root);
        root.querySelectorAll(SELECTOR).forEach(release);
    }

    new MutationObserver(muts => {
        muts.forEach(m => {
            m.addedNodes.forEach(scan);
            m.removedNodes.forEach(sweep);
        });
    }).observe(document.body, { childList: true, subtree: true });

    scan(document.body);

    // The theme changes tint only, but re-evaluate blur strength just in case.
    document.fonts && document.fonts.ready.then(() => document.querySelectorAll(SELECTOR).forEach(schedule));
})();
