// uses cloudflare workers ai to analyze http headers and create security assessments. 
// preprocesses headers via header-processor.ts to extract metadata, sends structured prompts to the ai model
// handles json parsing with character sanitization
// returns responses (AnalyzeResponse interface from types.ts)

import type { AnalyzeResponse } from "./types";
import { preprocessHeaders } from "./header-processor";

const SYSTEM_PROMPT = `You are HeaderGuard, a web security assistant specialized in analyzing HTTP security headers.

Your task is to analyze HTTP response headers and provide a comprehensive security assessment.

Evaluate the following security headers:
- Content-Security-Policy (CSP)
- Content-Security-Policy-Report-Only (CSP-Report-Only)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)

IMPORTANT GUIDELINES:
1. CSP-Report-Only: If Content-Security-Policy-Report-Only is present but Content-Security-Policy is missing, treat CSP as "partially implemented" (medium severity), not "missing" (high severity). The site is testing CSP in report-only mode.

2. X-XSS-Protection: This header is DEPRECATED. Do NOT recommend adding it if missing. If present with value "0", that is actually the correct modern practice (disabling the deprecated feature). Do not mark this as an issue.

3. Cookie Security: You will receive cookieStats metadata. Use this to assess cookie security instead of parsing raw Set-Cookie headers.

You must respond with a JSON object (and ONLY JSON, no markdown code blocks) that matches this exact structure:
{
  "score": <number between 0-100>,
  "summary": "<brief 1-2 sentence summary of overall security posture>",
  "issues": [
    {
      "name": "<short name of the issue>",
      "severity": "<low|medium|high>",
      "header": "<header name>",
      "current_value": "<actual value or null if missing>",
      "recommended_value": "<what should be set>",
      "explanation": "<why this matters, 1-2 sentences>"
    }
  ]
}

Scoring guidelines:
- 90-100: Excellent security posture with all critical headers properly configured
- 70-89: Good security with minor improvements needed
- 50-69: Moderate security with several missing or weak headers
- 30-49: Poor security with major vulnerabilities
- 0-29: Critical security issues, minimal protection

Severity guidelines:
- high: Missing or misconfigured headers that expose site to serious attacks (XSS, clickjacking, MITM)
- medium: Missing headers that reduce defense-in-depth but don't create immediate critical risks; or headers in report-only mode
- low: Minor improvements or optional headers`;

export async function analyzeHeaders(
	ai: Env["AI"],
	headers: Record<string, string>,
): Promise<AnalyzeResponse> {
	const processed = preprocessHeaders(headers);

	const userMessage = `Analyze these HTTP response headers and provide a security assessment in JSON format:

Headers:
${JSON.stringify(processed.rawHeaders, null, 2)}

Metadata:
- Has CSP: ${processed.metadata.hasCsp}
- Has CSP-Report-Only: ${processed.metadata.hasCspReportOnly}
- Has HSTS: ${processed.metadata.hasHsts}
- Cookie Stats: ${processed.metadata.cookieStats.total} total cookies
  - Secure: ${processed.metadata.cookieStats.secure}
  - HttpOnly: ${processed.metadata.cookieStats.httpOnly}
  - SameSite: ${processed.metadata.cookieStats.sameSite}

Remember to respond with ONLY valid JSON matching the exact structure specified in the system prompt.`;

	try {
		const response = await ai.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
			messages: [
				{ role: "system", content: SYSTEM_PROMPT },
				{ role: "user", content: userMessage },
			],
			response_format: { type: "json_object" },
			max_tokens: 2048,
		});

		console.log("AI response received:", JSON.stringify(response, null, 2));

		const result = response as { response: string };
		
		if (!result || !result.response) {
			console.error("Invalid response structure:", result);
			throw new Error(`Invalid response structure: ${JSON.stringify(result)}`);
		}

		let responseText = result.response.trim();
		console.log(`Response text length: ${responseText.length} characters`);
		console.log("Response text (first 500 chars):", responseText.substring(0, 500));
		console.log("Response text (last 200 chars):", responseText.substring(Math.max(0, responseText.length - 200)));

		if (responseText.startsWith("```")) {
			responseText = responseText.replace(/```json?\n?/g, "").replace(/```\n?$/g, "").trim();
		}

		const trimmed = responseText.trim();
		if (!trimmed.endsWith('}') && !trimmed.endsWith(']')) {
			console.error("JSON string appears incomplete. Last 100 chars:", trimmed.substring(Math.max(0, trimmed.length - 100)));
			throw new Error("AI response JSON appears to be truncated or incomplete");
		}

		let jsonText = responseText;
		if (responseText.startsWith('"') && responseText.endsWith('"')) {
			jsonText = JSON.parse(responseText);
		}

		if (typeof jsonText !== 'string') {
			throw new Error("Unexpected: jsonText is not a string");
		}

		let analysis: AnalyzeResponse;
		
		try {
			analysis = JSON.parse(jsonText);
		} catch (parseError) {
			const errorMsg = parseError instanceof Error ? parseError.message : String(parseError);
			console.warn("Initial JSON parse failed:", errorMsg);
			
			if (errorMsg.includes("control character") || errorMsg.includes("Bad control")) {
				let inString = false;
				let escapeNext = false;
				let result = '';
				
				for (let i = 0; i < jsonText.length; i++) {
					const char = jsonText[i];
					const prevChar = i > 0 ? jsonText[i - 1] : '';
					
					if (escapeNext) {
						result += char;
						escapeNext = false;
						continue;
					}
					
					if (char === '\\') {
						result += char;
						escapeNext = true;
						continue;
					}
					
					if (char === '"' && prevChar !== '\\') {
						inString = !inString;
						result += char;
						continue;
					}
					
					if (inString) {
						if (char === '\n') {
							result += '\\n';
						} else if (char === '\r') {
							result += '\\r';
						} else if (char === '\t') {
							result += '\\t';
						} else if (char === '\f') {
							result += '\\f';
						} else if (char === '\b') {
							result += '\\b';
						} else if (char.charCodeAt(0) < 32 && char !== '\n' && char !== '\r' && char !== '\t') {
							result += `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`;
						} else {
							result += char;
						}
					} else {
						result += char;
					}
				}
				
				console.log("Attempting to parse fixed JSON (control chars escaped)...");
				analysis = JSON.parse(result);
			} else {
				throw parseError;
			}
		}

		if (
			typeof analysis.score !== "number" ||
			typeof analysis.summary !== "string" ||
			!Array.isArray(analysis.issues)
		) {
			console.error("Invalid response structure:", analysis);
			throw new Error(`Invalid response structure: score=${typeof analysis.score}, summary=${typeof analysis.summary}, issues=${Array.isArray(analysis.issues)}`);
		}

		return analysis;
	} catch (error) {
		console.error("Error analyzing headers with AI:", error);
		console.error("Error details:", error instanceof Error ? error.message : String(error));
		console.error("Error stack:", error instanceof Error ? error.stack : "No stack trace");

		return {
			score: 50,
			summary:
				"Unable to complete AI analysis. Basic header check shows moderate security concerns.",
			issues: [
				{
					name: "Analysis Error",
					severity: "medium",
					header: "N/A",
					current_value: null,
					recommended_value: "N/A",
					explanation:
						"The AI analysis failed. Please try again or contact support if the issue persists.",
				},
			],
		};
	}
}
