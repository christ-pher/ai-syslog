import { $ } from 'bun';
import PocketBase from 'pocketbase';

//const pb = new PocketBase('http://0.0.0.0:8090');
const pb = new PocketBase('http://192.168.1.98:8090');

async function generate_prompt(logs: string) {
	return `Act as an experienced cybersecurity analyst (SOC/Tier-3). You will receive many lines, each a JSON record like the example (fields may include id, timestamp, hostname, device_type, facility, severity, priority, message, raw_log, source_ip, created, updated). For every line: parse JSON; if any field holds JSON-as-string, recursively parse to the final event object. Extract event details primarily from message/raw_log (e.g., program and pid from “name[pid]:”, IPs from “from X”, “src=”, “dst=”, HTTP method/URI/status); treat source_ip as the collector IP and prefer IPs found inside the event content. Using only the provided data, decide if the event suggests potentially malicious or policy-violating activity (e.g., SSH invalid/failed logins or brute force, sudo/su failures, suspicious process or command-line flags, encoded/obfuscated commands, reverse shell patterns, web attacks like SQLi/XSS/RCE/LFI/path traversal, IOC/signature hits, lateral movement, port scans/recon, unusual outbound connections, malware downloads, data exfiltration, persistence or cron/service/user changes, tampering with auth/system logs). Output nothing for benign lines. When at least one event is worth investigation, output a single JSON array (and nothing else) where each element is a compact object with keys: "index" (0-based line number), "id", "timestamp", "host" (hostname), "program" (from message/raw_log), "src_ip", "dst_ip", "severity", "reason" (concise ≤140 chars), and "event" (only the most relevant fields or a trimmed message excerpt). Omit any key whose value is unknown. Ensure valid JSON (no trailing commas) and do not include headings, counts, or summaries outside the array. If no events qualify, reply with exactly: No malicious activity detected, Here is the stringified JSON data: """${logs}"""`;
}

async function call_gemini(logs: string) {
	try {
		const gemini_resp = await $`gemini -p ${await generate_prompt(logs)}`.text();
		const gemini_resp_json = JSON.parse(gemini_resp.replace('```json', '').replace('```', ''));

		console.log(JSON.stringify(gemini_resp_json));
	} catch (e) {
		console.log("[]");
	}
}

async function get_logs() {
	try {
		const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString().replace("T", " ");
		const records = await pb.collection('logs').getFullList({
			filter: pb.filter('created >= {:cutoff}', { cutoff }),
			sort: '-created'
		});

		let str_logs = "";
		for (let x in records) {
			str_logs += JSON.stringify(records[x]) + "\n";
		}

		await call_gemini(str_logs);
	} catch (e) { console.log(e); }
}

await get_logs();
