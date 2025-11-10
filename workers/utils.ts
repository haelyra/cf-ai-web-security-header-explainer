// utility functs for url normalization, validation, header conversion, and smart fetching 
// used by app.ts to handle url processing and fetch operations
// detects cdn responses, asset files, bot protection, http-only sites, and non-200 status codes to prevent inaccurate scores


export interface CDNDetectionResult {
	isCDN: true;
	detectedServer: string;
	headerCount: number;
	message: string;
}

export interface HTTPOnlyWarning {
	isHTTPOnly: true;
	message: string;
}

export interface AssetURLWarning {
	isAsset: true;
	extension: string;
	message: string;
}

export interface Non200StatusWarning {
	isNon200: true;
	statusCode: number;
	statusText: string;
	message: string;
}

export interface BotProtectionWarning {
	isBotProtection: true;
	detectedType: string;
	message: string;
}

export interface SuccessfulFetchResult {
	isCDN: false;
	isHTTPOnly: false;
	isAsset: false;
	isNon200: false;
	isBotProtection: false;
	response: Response;
	headers: Record<string, string>;
	contentType: string | null;
}

export type FetchResult =
	| CDNDetectionResult
	| HTTPOnlyWarning
	| AssetURLWarning
	| Non200StatusWarning
	| BotProtectionWarning
	| SuccessfulFetchResult;

export function normalizeUrl(url: string): string {
	let trimmed = url.trim();

	if (trimmed.match(/^https?:\/\//i)) {
		return trimmed;
	}

	const baredomainPattern = /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/.*)?$/;

	if (baredomainPattern.test(trimmed)) {
		if (!trimmed.startsWith("www.")) {
			trimmed = `www.${trimmed}`;
		}
	}

	return `https://${trimmed}`;
}

export function isValidUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		return parsed.protocol === "http:" || parsed.protocol === "https:";
	} catch {
		return false;
	}
}

export function headersToObject(headers: Headers): Record<string, string> {
	const result: Record<string, string> = {};

	headers.forEach((value, key) => {
		result[key.toLowerCase()] = value;
	});

	return result;
}

export function getCacheKey(url: string): string {
	return `header-analysis:${normalizeUrl(url)}`;
}

function isAssetURL(url: URL): string | null {
	const assetExtensions = [
		".png",
		".jpg",
		".jpeg",
		".gif",
		".webp",
		".svg",
		".ico",
		".css",
		".js",
		".json",
		".xml",
		".pdf",
		".woff",
		".woff2",
		".ttf",
		".eot",
	];
	const pathname = url.pathname.toLowerCase();
	for (const ext of assetExtensions) {
		if (pathname.endsWith(ext)) {
			return ext;
		}
	}
	return null;
}

function isBotProtectionResponse(
	headers: Record<string, string>,
	statusCode: number,
): string | null {
	if (
		headers["server"]?.toLowerCase() === "cloudflare" &&
		headers["cf-chl-bypass"]
	) {
		return "Cloudflare Challenge";
	}

	if (statusCode === 429) {
		return "Rate Limited (429)";
	}

	if (statusCode === 503) {
		return "Service Unavailable (503) - Possible WAF/bot protection";
	}

	if (headers["server"]?.toLowerCase().includes("akamaighost")) {
		return "Akamai Bot Protection";
	}

	return null;
}

export async function fetchWithSmartFallback(
	url: string,
): Promise<FetchResult> {
	const normalizedUrl = new URL(url);

	if (normalizedUrl.protocol === "http:") {
		return {
			isHTTPOnly: true,
			message:
				"This site is using HTTP instead of HTTPS. All modern websites should migrate to HTTPS for security. HTTP traffic is unencrypted and vulnerable to man-in-the-middle attacks.",
		};
	}

	const assetExt = isAssetURL(normalizedUrl);
	if (assetExt) {
		return {
			isAsset: true,
			extension: assetExt,
			message: `This appears to be a direct link to an asset file (${assetExt}). Security headers are typically analyzed for HTML pages, not individual assets. Please enter a page URL instead.`,
		};
	}

	const headersToSend = {
		"User-Agent":
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:
			"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	};

	let res: Response;
	try {
		res = await fetch(normalizedUrl.toString(), {
			method: "HEAD",
			headers: headersToSend,
			redirect: "follow",
			signal: AbortSignal.timeout(10000),
		});
	} catch (error) {
		throw error;
	}

	const headers = headersToObject(res.headers);
	const serverHeader = headers["server"]?.toLowerCase() || "";
	const contentType = headers["content-type"] || null;

	if (res.status !== 200) {
		return {
			isNon200: true,
			statusCode: res.status,
			statusText: res.statusText,
			message: `Cannot reliably analyze this URL (HTTP ${res.status} ${res.statusText}). The server returned a non-success response. This could be a redirect, error page, or access restriction. Try a different URL or page.`,
		};
	}

	const botProtection = isBotProtectionResponse(headers, res.status);
	if (botProtection) {
		return {
			isBotProtection: true,
			detectedType: botProtection,
			message: `This site is serving a challenge or bot protection page (${botProtection}). The headers analyzed would be from the protection layer, not your actual site. This makes the analysis unreliable.`,
		};
	}

	if (
		contentType &&
		!contentType.includes("text/html") &&
		!contentType.includes("application/xhtml")
	) {
		return {
			isNon200: true,
			statusCode: res.status,
			statusText: `Non-HTML Content (${contentType})`,
			message: `This URL returns ${contentType} instead of HTML. Security header analysis is designed for web pages (text/html), not APIs or other content types. The scoring may not be meaningful.`,
		};
	}

	if (/akamai|ghost|netstorage/.test(serverHeader)) {
		return {
			isCDN: true,
			detectedServer: serverHeader,
			headerCount: Object.keys(headers).length,
			message:
				"Response appears to come from a CDN edge (e.g., Akamai) rather than an origin server. Try fetching a deeper path like /en-us/ or /home.",
		};
	}

	if (Object.keys(headers).length < 5) {
		const altPaths = ["/en-us/", "/index.html", "/home", "/about"];

		for (const path of altPaths) {
			try {
				const retryUrl = new URL(path, normalizedUrl.origin);
				const retryRes = await fetch(retryUrl.toString(), {
					method: "HEAD",
					headers: headersToSend,
					redirect: "follow",
					signal: AbortSignal.timeout(10000),
				});
				const retryHeaders = headersToObject(retryRes.headers);
				const retryContentType = retryHeaders["content-type"] || null;

				if (
					retryRes.status === 200 &&
					Object.keys(retryHeaders).length >= 5
				) {
					console.log(
						`Found richer headers at ${retryUrl.toString()}: ${Object.keys(retryHeaders).length} headers`,
					);
					return {
						isCDN: false,
						isHTTPOnly: false,
						isAsset: false,
						isNon200: false,
						isBotProtection: false,
						response: retryRes,
						headers: retryHeaders,
						contentType: retryContentType,
					};
				}
			} catch (error) {
				console.log(`Failed to fetch ${path}:`, error);
				continue;
			}
		}

		return {
			isCDN: true,
			detectedServer: serverHeader || "unknown",
			headerCount: Object.keys(headers).length,
			message:
				"Header fetch returned too few headers (<5). Likely a CDN edge or static asset response. Try a deeper route manually.",
		};
	}

	return {
		isCDN: false,
		isHTTPOnly: false,
		isAsset: false,
		isNon200: false,
		isBotProtection: false,
		response: res,
		headers: headers,
		contentType: contentType,
	};
}
