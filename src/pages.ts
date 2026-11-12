export function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

const STYLE = `
	:root { color-scheme: light dark; }
	body { font: 16px/1.5 system-ui, sans-serif; margin: 0; padding: 16px; background: Canvas; color: CanvasText; }
	main { max-width: 34rem; margin: 10vh auto 0; }
	h1 { font-size: 1.5rem; line-height: 1.25; }
	.destination { font: 1.125rem ui-monospace, monospace; padding: 12px 16px; border: 1px solid GrayText; border-radius: 8px; overflow-wrap: anywhere; }
	.button { display: inline-block; margin-top: 8px; padding: 10px 20px; border-radius: 8px; background: #0b5fff; color: #fff; text-decoration: none; font-weight: 600; }
	small { display: block; margin-top: 32px; color: GrayText; }
`;

function page(title: string, body: string, status: number): Response {
	const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;

	return new Response(html, {
		status,
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'no-store',
			'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
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
