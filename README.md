# CF AI Header Guard

An AI-powered HTTP header security analyzer built with Cloudflare Workers AI and KV.  
It fetches and evaluates site headers, detects CDN edge responses, and scores security posture using Llama 3.3.

Deployed link: https://cf-ai-web-security-header-explainer.haleyfchen.workers.dev/

## Features
- Real-time header fetching and analysis
- AI scoring and issue explanations
- Automatic CDN detection and path fallback
- KV caching for fast repeat analysis
- Built with Hono + Workers AI

## Stack
- Cloudflare Workers AI (`@cf/llama-3.3-8b-instruct`)
- KV storage
- Hono.js
- Wrangler for deployment

## Run Locally
```bash
npm install
npm run dev
