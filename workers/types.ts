// type defs 

export interface AnalyzeRequest {
	url: string;
	bypass_cache?: boolean;
}

export type IssueSeverity = "low" | "medium" | "high";

export interface SecurityIssue {
	name: string;
	severity: IssueSeverity;
	header: string;
	current_value: string | null;
	recommended_value: string;
	explanation: string;
}

export interface AnalyzeResponse {
	score: number;
	summary: string;
	issues: SecurityIssue[];
	warning?: {
		type: "cdn" | "asset" | "non-200" | "bot-protection" | "http-only";
		message: string;
		details?: {
			detectedServer?: string;
			headerCount?: number;
			statusCode?: number;
			extension?: string;
		};
	};
	cdnWarning?: {
		detectedServer: string;
		headerCount: number;
		message: string;
	};
}
