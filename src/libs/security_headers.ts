export function securityHeaders(_req, res, next): void {
	res.header("X-Content-Type-Options", "nosniff");
	res.header("X-Frame-Options", "DENY");
	res.header("Referrer-Policy", "no-referrer");
	res.header(
		"Content-Security-Policy",
		[
			"default-src 'self'",
			"script-src 'self' https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
			"font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
			"img-src 'self' data:",
			"connect-src 'self'",
			"frame-ancestors 'none'",
		].join("; ")
	);
	next();
}
