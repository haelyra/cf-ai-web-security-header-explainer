
import { Hono } from "hono";
import { createRequestHandler } from "react-router";
import type { AnalyzeRequest, AnalyzeResponse } from "./types";
import {
	normalizeUrl,
	isValidUrl,
	getCacheKey,
	fetchWithSmartFallback,
} from "./utils";
import { analyzeHeaders } from "./analyzer";

const app = new Hono<{ Bindings: Env }>();

app.post("/api/analyze", async (c) => {
	try {
		const body = await c.req.json<AnalyzeRequest>();

		if (!body.url) {
			return c.json({ error: "URL is required" }, 400);
		}

		const normalizedUrl = normalizeUrl(body.url);

		if (!isValidUrl(normalizedUrl)) {
			return c.json({ error: "Invalid URL format" }, 400);
		}

		const cacheKey = getCacheKey(normalizedUrl);

		const bypassCache = body.bypass_cache === true || c.req.query("bypass_cache") === "true";
		
		if (!bypassCache) {
			const cached = await c.env.HEADER_CACHE.get<AnalyzeResponse>(
				cacheKey,
				"json",
			);
			if (cached) {
				console.log(`Cache hit for ${normalizedUrl}`);
				return c.json(cached);
			}
		} else {
			console.log(`Cache bypassed for ${normalizedUrl}`);
		}

		console.log(`Cache miss for ${normalizedUrl}, fetching headers...`);

		let fetchResult;
		try {
			fetchResult = await fetchWithSmartFallback(normalizedUrl);
		} catch (fetchError) {
			console.error("Error fetching URL:", fetchError);

			const errorMsg = fetchError instanceof Error ? fetchError.message : String(fetchError);
			let userMessage = "Failed to fetch URL. ";

			if (errorMsg.includes("timeout") || errorMsg.includes("timed out")) {
				userMessage += "The request timed out. The site may be very slow or unreachable.";
			} else if (errorMsg.includes("DNS") || errorMsg.includes("ENOTFOUND")) {
				userMessage += "Could not resolve the domain name. Please check the URL is correct.";
			} else if (errorMsg.includes("connection")) {
				userMessage += "Could not connect to the server. The site may be down or blocking requests.";
			} else {
				userMessage += "Please check that the URL is accessible and try again.";
			}

			return c.json({ error: userMessage }, 400);
		}

		if ("isHTTPOnly" in fetchResult && fetchResult.isHTTPOnly) {
			return c.json({
				score: 10,
				summary: fetchResult.message,
				issues: [{
					name: "HTTP Only (No HTTPS)",
					severity: "high" as const,
					header: "Transport Protocol",
					current_value: "HTTP",
					recommended_value: "HTTPS",
					explanation: "This site is not using HTTPS. Migrate to HTTPS immediately for basic security."
				}],
			});
		}

		if ("isAsset" in fetchResult && fetchResult.isAsset) {
			return c.json({
				score: 0,
				summary: "Unable to analyze: This URL points to an asset file, not a web page.",
				issues: [],
				warning: {
					type: "asset" as const,
					message: fetchResult.message,
					details: {
						extension: fetchResult.extension,
					},
				},
			});
		}

		if ("isNon200" in fetchResult && fetchResult.isNon200) {
			return c.json({
				score: 0,
				summary: "Unable to analyze: The server returned a non-success response.",
				issues: [],
				warning: {
					type: "non-200" as const,
					message: fetchResult.message,
					details: {
						statusCode: fetchResult.statusCode,
					},
				},
			});
		}

		if ("isBotProtection" in fetchResult && fetchResult.isBotProtection) {
			return c.json({
				score: 0,
				summary: "Unable to analyze: Bot protection or challenge detected.",
				issues: [],
				warning: {
					type: "bot-protection" as const,
					message: fetchResult.message,
					details: {
						detectedServer: fetchResult.detectedType,
					},
				},
			});
		}

		if ("isCDN" in fetchResult && fetchResult.isCDN) {
			console.log(
				`CDN detected for ${normalizedUrl}:`,
				fetchResult.detectedServer,
			);
			return c.json({
				score: 0,
				summary: "Unable to analyze: CDN edge response detected.",
				issues: [],
				warning: {
					type: "cdn" as const,
					message: fetchResult.message,
					details: {
						detectedServer: fetchResult.detectedServer,
						headerCount: fetchResult.headerCount,
					},
				},
			});
		}
		

		const headers = fetchResult.headers;
		console.log(`Fetched headers for ${normalizedUrl}:`, headers);

		const analysis = await analyzeHeaders(c.env.AI, headers);

		await c.env.HEADER_CACHE.put(cacheKey, JSON.stringify(analysis), {
			expirationTtl: 86400,
		});

		console.log(`Stored analysis in cache for ${normalizedUrl}`);

		return c.json(analysis);
	} catch (error) {
		console.error("Error analyzing URL:", error);
		return c.json(
			{
				error:
					"Failed to analyze URL. Please check the URL and try again. " +
					(error instanceof Error ? error.message : ""),
			},
			500,
		);
	}
});

app.get("/api/test-ai", async (c) => {
	const result = await c.env.AI.run("@cf/meta/llama-3-8b-instruct", {
		messages: [
			{ role: "system", content: "You are a helpful assistant." },
			{ role: "user", content: "Say 'Workers AI is ready!'" },
		],
	});
	return c.json(result);
});

app.post("/api/clear-cache", async (c) => {
	try {
		const body = await c.req.json<{ url?: string }>();
		
		if (body.url) {
			const normalizedUrl = normalizeUrl(body.url);
			const cacheKey = getCacheKey(normalizedUrl);
			await c.env.HEADER_CACHE.delete(cacheKey);
			return c.json({ success: true, message: `Cache cleared for ${normalizedUrl}` });
		} else {
			return c.json({ error: "URL is required" }, 400);
		}
	} catch (error) {
		return c.json({ error: "Failed to clear cache" }, 500);
	}
});

app.get("*", (c) => {
	const requestHandler = createRequestHandler(
		() => import("virtual:react-router/server-build"),
		import.meta.env.MODE,
	);

	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx },
	});
});

export default app;
