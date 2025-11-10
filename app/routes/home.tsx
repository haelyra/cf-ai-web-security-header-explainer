import type { Route } from "./+types/home";
import { HeaderGuard } from "../components/HeaderGuard";

export function meta({}: Route.MetaArgs) {
	return [
		{ title: "HeaderGuard - HTTP Security Header Analyzer" },
		{
			name: "description",
			content:
				"Analyze HTTP security headers and get recommendations to improve your website's security posture.",
		},
	];
}

export default function Home() {
	return <HeaderGuard />;
}
