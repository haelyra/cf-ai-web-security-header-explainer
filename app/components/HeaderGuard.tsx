import { useState, useEffect } from "react";
import type {
	AnalyzeRequest,
	AnalyzeResponse,
	ApiError,
	IssueSeverity,
	SecurityIssue,
} from "../types/api";

const LOADING_MESSAGES = [
	"Initiating connection...",
	"Fetching HTTP headers...",
	"Analyzing security configuration...",
	"Evaluating header policies...",
	"Generating recommendations...",
];

export function HeaderGuard() {
	const [url, setUrl] = useState("");
	const [loading, setLoading] = useState(false);
	const [loadingMessageIndex, setLoadingMessageIndex] = useState(0);
	const [result, setResult] = useState<AnalyzeResponse | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [bypassCache, setBypassCache] = useState(false);

	useEffect(() => {
		if (!loading) {
			setLoadingMessageIndex(0);
			return;
		}

		const interval = setInterval(() => {
			setLoadingMessageIndex((prev) => (prev + 1) % LOADING_MESSAGES.length);
		}, 1500);

		return () => clearInterval(interval);
	}, [loading]);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		if (!url.trim()) {
			setError("Please enter a URL");
			return;
		}

		setLoading(true);
		setError(null);
		setResult(null);

		try {
			const requestBody: AnalyzeRequest = { 
				url: url.trim(),
				bypass_cache: bypassCache 
			};

			const response = await fetch("/api/analyze", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify(requestBody),
			});

			if (!response.ok) {
				const errorData: ApiError = await response.json();
				throw new Error(errorData.error || "Failed to analyze URL");
			}

			const data: AnalyzeResponse = await response.json();
			setResult(data);
		} catch (err) {
			setError(
				err instanceof Error ? err.message : "An unexpected error occurred",
			);
		} finally {
			setLoading(false);
		}
	};

	return (
		<main className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 py-12 px-4">
			<div className="max-w-4xl mx-auto">
				<div className="text-center mb-12">
					<h1 className="text-5xl font-bold text-gray-900 dark:text-white mb-4">
						HeaderGuard
					</h1>
					<p className="text-xl text-gray-600 dark:text-gray-300">
						HTTP Security Header Analyzer
					</p>
				</div>

				<div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8 mb-8">
					<form onSubmit={handleSubmit} className="space-y-4">
						<div>
							<label
								htmlFor="url-input"
								className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
							>
								Enter URL to analyze
							</label>
							<input
								id="url-input"
								type="text"
								value={url}
								onChange={(e) => setUrl(e.target.value)}
								placeholder="example.com or https://example.com"
								className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white text-lg"
								disabled={loading}
							/>
						</div>
						<div className="flex items-center">
							<input
								id="bypass-cache"
								type="checkbox"
								checked={bypassCache}
								onChange={(e) => setBypassCache(e.target.checked)}
								className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
								disabled={loading}
							/>
							<label
								htmlFor="bypass-cache"
								className="ml-2 text-sm text-gray-700 dark:text-gray-300"
							>
								Bypass cache (force fresh analysis)
							</label>
						</div>
						<button
							type="submit"
							disabled={loading}
							className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-6 rounded-lg transition-colors duration-200 text-lg"
						>
							{loading ? "Analyzing..." : "Analyze"}
						</button>

						{loading && (
							<div className="mt-4 space-y-2">
								<div className="flex items-center justify-center gap-2 text-blue-600 dark:text-blue-400">
									<svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
										<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
										<path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
									</svg>
									<span className="text-sm font-medium">{LOADING_MESSAGES[loadingMessageIndex]}</span>
								</div>
								<div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1 overflow-hidden">
									<div className="bg-blue-600 h-1 rounded-full animate-pulse" style={{ width: '100%' }}></div>
								</div>
							</div>
						)}
					</form>
				</div>

				{error && (
					<div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-8">
						<p className="text-red-800 dark:text-red-200">{error}</p>
					</div>
				)}

				{result && (
					<div className="space-y-6">
						{(result.warning || result.cdnWarning) && (
							<div className="bg-yellow-50 dark:bg-yellow-900/20 border-2 border-yellow-400 dark:border-yellow-600 rounded-2xl p-6">
								<div className="flex items-start gap-4">
									<div className="flex-shrink-0">
										<svg
											className="w-8 h-8 text-yellow-600 dark:text-yellow-400"
											fill="none"
											strokeLinecap="round"
											strokeLinejoin="round"
											strokeWidth="2"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
										</svg>
									</div>
									<div className="flex-1">
										<h3 className="text-xl font-bold text-yellow-900 dark:text-yellow-200 mb-2">
											{result.warning?.type === "cdn" && "CDN Edge Response Detected"}
											{result.warning?.type === "asset" && "Asset File Detected"}
											{result.warning?.type === "non-200" && "Non-Success Response"}
											{result.warning?.type === "bot-protection" && "Bot Protection Detected"}
											{result.warning?.type === "http-only" && "HTTP Only (No HTTPS)"}
											{!result.warning && result.cdnWarning && "CDN Edge Response Detected"}
										</h3>
										<p className="text-yellow-800 dark:text-yellow-300 mb-3">
											{result.warning?.message || result.cdnWarning?.message}
										</p>
										{result.warning?.details && (
											<div className="bg-yellow-100 dark:bg-yellow-900/40 rounded-lg p-3 text-sm space-y-1">
												{result.warning.details.detectedServer && (
													<p className="text-yellow-900 dark:text-yellow-200">
														<span className="font-semibold">Detected:</span>{" "}
														{result.warning.details.detectedServer}
													</p>
												)}
												{result.warning.details.headerCount !== undefined && (
													<p className="text-yellow-900 dark:text-yellow-200">
														<span className="font-semibold">Headers Found:</span>{" "}
														{result.warning.details.headerCount}
													</p>
												)}
												{result.warning.details.statusCode && (
													<p className="text-yellow-900 dark:text-yellow-200">
														<span className="font-semibold">Status Code:</span>{" "}
														{result.warning.details.statusCode}
													</p>
												)}
												{result.warning.details.extension && (
													<p className="text-yellow-900 dark:text-yellow-200">
														<span className="font-semibold">File Type:</span>{" "}
														{result.warning.details.extension}
													</p>
												)}
											</div>
										)}
										{!result.warning && result.cdnWarning && (
											<div className="bg-yellow-100 dark:bg-yellow-900/40 rounded-lg p-3 text-sm space-y-1">
												<p className="text-yellow-900 dark:text-yellow-200">
													<span className="font-semibold">Detected Server:</span>{" "}
													{result.cdnWarning.detectedServer || "unknown"}
												</p>
												<p className="text-yellow-900 dark:text-yellow-200">
													<span className="font-semibold">Headers Found:</span>{" "}
													{result.cdnWarning.headerCount}
												</p>
											</div>
										)}
										{result.warning?.type === "cdn" && (
											<p className="text-yellow-800 dark:text-yellow-300 mt-3 text-sm">
												💡 Tip: Try analyzing a specific page like{" "}
												<code className="bg-yellow-200 dark:bg-yellow-900 px-1 py-0.5 rounded">
													{url}/home
												</code>{" "}
												or{" "}
												<code className="bg-yellow-200 dark:bg-yellow-900 px-1 py-0.5 rounded">
													{url}/about
												</code>{" "}
												to get more accurate results.
											</p>
										)}
									</div>
								</div>
							</div>
						)}

						{!result.warning && !result.cdnWarning && (
							<div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8 text-center">
								<div className="inline-flex items-center justify-center">
									<div
										className={`text-6xl font-bold ${getScoreColor(result.score)}`}
									>
										{result.score}
									</div>
									<div className="text-3xl text-gray-400 dark:text-gray-500 ml-2">
										/ 100
									</div>
								</div>
								<p className="text-gray-600 dark:text-gray-300 mt-4 text-lg">
									{result.summary}
								</p>
							</div>
						)}

						{result.issues.length > 0 && (
							<div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8">
								<h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
									Security Issues ({result.issues.length})
								</h2>
								<div className="space-y-6">
									{result.issues.map((issue, index) => (
										<IssueCard key={index} issue={issue} />
									))}
								</div>
							</div>
						)}
					</div>
				)}
			</div>
		</main>
	);
}

interface IssueCardProps {
	issue: SecurityIssue;
}

function IssueCard({ issue }: IssueCardProps) {
	return (
		<div className="border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-md transition-shadow">
			{/* Issue Header */}
			<div className="flex items-start justify-between mb-4">
				<h3 className="text-xl font-semibold text-gray-900 dark:text-white">
					{issue.name}
				</h3>
				<SeverityBadge severity={issue.severity} />
			</div>

			<p className="text-gray-700 dark:text-gray-300 mb-4">
				{issue.explanation}
			</p>

			<div className="space-y-3">
				<div>
					<p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
						Header: <span className="text-gray-900 dark:text-white font-mono">{issue.header}</span>
					</p>
				</div>

				<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
							Current Value:
						</p>
						<pre className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3 text-sm overflow-x-auto">
							<code className="text-gray-800 dark:text-gray-200">
								{issue.current_value || "(not set)"}
							</code>
						</pre>
					</div>

					<div>
						<p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
							Recommended Value:
						</p>
						<pre className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3 text-sm overflow-x-auto">
							<code className="text-green-800 dark:text-green-200">
								{issue.recommended_value}
							</code>
						</pre>
					</div>
				</div>
			</div>
		</div>
	);
}

interface SeverityBadgeProps {
	severity: IssueSeverity;
}

function SeverityBadge({ severity }: SeverityBadgeProps) {
	const colors = {
		high: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
		medium:
			"bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300",
		low: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
	};

	return (
		<span
			className={`px-3 py-1 rounded-full text-sm font-semibold uppercase ${colors[severity]}`}
		>
			{severity}
		</span>
	);
}

function getScoreColor(score: number): string {
	if (score >= 90) return "text-green-600 dark:text-green-400";
	if (score >= 70) return "text-blue-600 dark:text-blue-400";
	if (score >= 50) return "text-orange-600 dark:text-orange-400";
	return "text-red-600 dark:text-red-400";
}
