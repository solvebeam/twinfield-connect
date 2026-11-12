export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

const STYLE = `
	:root { color-scheme: light dark; --accent: #007bc1; --border: #d9dee3; --muted: #5f6b76; --surface: #fff; --page: #f4f7f9; }
	@media (prefers-color-scheme: dark) {
		:root { --accent: #3ea6e3; --border: #2c343c; --muted: #9aa5b1; --surface: #171c21; --page: #0e1215; }
	}
	* { box-sizing: border-box; }
	body { font: 16px/1.5 system-ui, sans-serif; margin: 0; padding: 16px; background: var(--page); color: CanvasText; }
	.wrap { max-width: 34rem; margin: 6vh auto 0; }
	header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; font-weight: 600; }
	main { padding: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; }
	h1 { margin-top: 0; font-size: 1.5rem; line-height: 1.25; }
	a { color: var(--accent); }
	.destination { font: 1.125rem ui-monospace, monospace; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; overflow-wrap: anywhere; }
	.button { display: inline-block; margin-top: 8px; padding: 10px 20px; border-radius: 8px; background: #007bc1; color: #fff; text-decoration: none; font-weight: 600; }
	small { display: block; margin-top: 24px; color: var(--muted); }
	main > :last-child { margin-bottom: 0; }
	footer { margin-top: 24px; color: var(--muted); font-size: 0.8125rem; text-align: center; }
	.brands { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: 12px; }
	.brand { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 16px; border: 1px solid var(--border); border-radius: 12px; color: inherit; text-decoration: none; }
	.brand:hover { border-color: var(--accent); }
	.brand img { display: block; width: auto; max-width: 100%; }
	footer p { margin: 16px 0 0; }
`;

/** A logo from `public/brand/` with a variant for dark mode. */
function logo(name: string, alt: string, height: number): string {
	return `<picture><source srcset="/brand/${name}-dark.svg" media="(prefers-color-scheme: dark)"><img src="/brand/${name}.svg" alt="${alt}" height="${height}"></picture>`;
}

const HEADER = `<header><img src="/brand/twinfield-icon.svg" alt="" width="28" height="28"> Twinfield Connect</header>`;

const FOOTER = `<footer>
<div class="brands">
<a class="brand" href="https://www.solvebeam.com/" rel="noreferrer">Made by ${logo('solvebeam-logo', 'SolveBeam', 28)}</a>
<a class="brand" href="https://www.twinfield.com/" rel="noreferrer">Twinfield is a product of ${logo('wolters-kluwer-logo', 'Wolters Kluwer', 24)}</a>
</div>
<p>Twinfield and Wolters Kluwer are trademarks of Wolters Kluwer. Their names and logos are used only to refer to their products.</p>
</footer>`;

function page(title: string, body: string, status: number): Response {
	const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
${HEADER}
<main>
${body}
</main>
${FOOTER}
</div>
</body>
</html>`;

	return new Response(html, {
		status,
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'no-store',
			'Content-Security-Policy': "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
			'Referrer-Policy': 'no-referrer',
			'X-Content-Type-Options': 'nosniff',
			'X-Frame-Options': 'DENY',
		},
	});
}

/**
 * The page between the application and Twinfield. Twinfield shows the name of the SolveBeam client
 * on its consent screen, so this is the only place where the user sees who really gets access.
 */
export function consentPage(clientName: string, redirectUri: string, twinfieldUrl: string): Response {
	const destination = new URL(redirectUri).host;

	return page(
		'Connect to Twinfield',
		`<h1>${escapeHtml(clientName)} wants to connect to Twinfield</h1>
<p>After you log in at Twinfield, access to your Twinfield organisation is given to the application at:</p>
<p class="destination">${escapeHtml(destination)}</p>
<p>Only continue if you recognise this address and started this yourself.</p>
<p><a class="button" href="${escapeHtml(twinfieldUrl)}" rel="noreferrer">Continue to Twinfield</a></p>
<small>This connection runs through the Twinfield client of SolveBeam. Twinfield will show that name when it asks for your permission.</small>`,
		200,
	);
}

export function errorPage(message: string, status = 400): Response {
	return page(
		'Cannot connect to Twinfield',
		`<h1>Cannot connect to Twinfield</h1>
<p>${escapeHtml(message)}</p>
<p>Go back to the application and try again.</p>`,
		status,
	);
}

export function homePage(): Response {
	return page(
		'Twinfield Connect',
		`<h1>Twinfield Connect</h1>
<p>An OAuth proxy that lets applications connect to Twinfield through the certified Twinfield client of SolveBeam.</p>
<p>Use it with the <a href="https://php.twinfield.solvebeam.com">Twinfield PHP SDK</a>.</p>`,
		200,
	);
}
