// header preprocessing 
// analyzes cookies, detects csp and hsts presence, and provides metadata to analyzer.ts
// improves analysis quality by giving context about headers

export interface ProcessedHeaders {
	rawHeaders: Record<string, string>;
	metadata: {
		hasCsp: boolean;
		hasCspReportOnly: boolean;
		hasHsts: boolean;
		cookieStats: {
			total: number;
			secure: number;
			httpOnly: number;
			sameSite: number;
		};
	};
}

function analyzeCookies(setCookieHeader: string | undefined): {
	total: number;
	secure: number;
	httpOnly: number;
	sameSite: number;
} {
	if (!setCookieHeader) {
		return { total: 0, secure: 0, httpOnly: 0, sameSite: 0 };
	}

	const cookies = setCookieHeader.split(/,\s*(?=[a-zA-Z0-9_-]+=)/).filter(Boolean);

	let secure = 0;
	let httpOnly = 0;
	let sameSite = 0;

	for (const cookie of cookies) {
		const lowerCookie = cookie.toLowerCase();
		if (lowerCookie.includes("secure")) secure++;
		if (lowerCookie.includes("httponly")) httpOnly++;
		if (lowerCookie.includes("samesite")) sameSite++;
	}

	return {
		total: cookies.length,
		secure,
		httpOnly,
		sameSite,
	};
}

export function preprocessHeaders(
	headers: Record<string, string>,
): ProcessedHeaders {
	const hasCsp = !!headers["content-security-policy"];
	const hasCspReportOnly = !!headers["content-security-policy-report-only"];
	const hasHsts = !!headers["strict-transport-security"];

	const cookieStats = analyzeCookies(headers["set-cookie"]);

	return {
		rawHeaders: headers,
		metadata: {
			hasCsp,
			hasCspReportOnly,
			hasHsts,
			cookieStats,
		},
	};
}
