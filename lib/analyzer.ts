export type RiskClass = "Low Risk" | "Suspicious" | "High Risk";
export type Indicator = { title: string; detail: string; points: number };
export type Analysis = { score: number; classification: RiskClass; indicators: Indicator[]; recommendations: string[] };

export function classify(score: number): RiskClass {
  return score >= 60 ? "High Risk" : score >= 30 ? "Suspicious" : "Low Risk";
}

function result(indicators: Indicator[], recommendations: string[]): Analysis {
  const score = Math.min(100, indicators.reduce((sum, item) => sum + item.points, 0));
  return { score, classification: classify(score), indicators, recommendations };
}

const add = (list: Indicator[], title: string, detail: string, points: number) => list.push({ title, detail, points });
const suspiciousPhrases = [
  [/(act now|immediately|urgent|within\s+\d+\s+hours?|account.{0,20}(suspend|close|lock)|final notice)/i, "Urgency or threat", "Pressure language tries to rush a decision.", 18],
  [/(verify|confirm|validate).{0,35}(account|identity|details|payment)|account.{0,20}(verification|required)/i, "Account verification request", "The message asks for sensitive account confirmation.", 18],
  [/(password|passcode|one[- ]time code|\botp\b|security code).{0,30}(send|reply|share|provide|confirm|enter)|(?:send|reply|share|provide).{0,30}(password|passcode|\botp\b|security code)/i, "Credential or code request", "Legitimate support teams should not ask you to send a password or one-time code.", 35],
  [/(click|tap|follow).{0,20}(link|below|here)|\b(?:login|sign in)\s+to\s+(?:avoid|prevent|restore)/i, "Call to follow a link", "The message directs you to a link to resolve an account issue.", 12],
  [/(wire transfer|gift card|payment overdue|invoice attached|prize winner|claim your reward)/i, "Common fraud language", "This wording is often used in payment or reward scams.", 20],
];

export function analyzeEmail(input: { message: string; sender?: string; displayName?: string }): Analysis {
  const { message } = input;
  if (message.length > 20000) return result([{ title: "Message too long", detail: "Analysis is limited to 20,000 characters.", points: 0 }], ["Paste a shorter, redacted excerpt. Do not include real credentials or private data."]);
  const header = message.match(/^\s*from:\s*(.*?)\s*$/im)?.[1] ?? "";
  const headerAddress = header.match(/<([^<>\s]+@[^<>\s]+)>/)?.[1] ?? "";
  const sender = input.sender || headerAddress;
  const displayName = input.displayName || (headerAddress ? header.replace(/<[^>]+>/, "").replace(/^\s*["']|["']\s*$/g, "").trim() : "");
  const indicators: Indicator[] = [];
  for (const [pattern, title, detail, points] of suspiciousPhrases) if ((pattern as RegExp).test(message)) add(indicators, title as string, detail as string, points as number);
  const links = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) ?? [];
  if (links.length) add(indicators, "Link present", `${links.length} URL${links.length === 1 ? "" : "s"} found; inspect the domain before opening.`, 8 + Math.min(12, (links.length - 1) * 4));
  if (/(attached|attachment|open the file|enable macros|document attached|invoice\.pdf)/i.test(message)) add(indicators, "Attachment mentioned", "Unexpected files can carry malware or lead to credential theft.", 14);
  if (sender && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sender.trim())) add(indicators, "Unusual sender address", "The supplied sender does not look like a normal email address.", 24);
  if (sender && /^[a-z]{5,}\d{3,}@/i.test(sender.trim())) add(indicators, "Unusual sender identifier", "This address has a random-looking name followed by several digits. That can occur in legitimate accounts, but it is a reason to verify the sender through another channel.", 30);
  if (sender) add(indicators, "Sender domain not verified", "This local scan did not check whether the domain exists, accepts email, or belongs to the claimed sender. A valid-looking address alone does not prove the sender is genuine.", 0);
  if (sender && /@(gmail|yahoo|outlook|hotmail)\./i.test(sender) && /(bank|university|microsoft|apple|paypal|amazon|support|helpdesk|security|administrator|\bIT\b|billing)/i.test(displayName)) add(indicators, "Sender and display name mismatch", "A public mailbox is paired with an organization or support name. Sender names can be spoofed.", 30);
  if (displayName && sender && !/@(gmail|yahoo|outlook|hotmail)\./i.test(sender)) {
    const senderHost = sender.split("@")[1]?.toLowerCase() ?? "";
    const name = displayName.toLowerCase().replace(/[^a-z0-9]/g, "");
    const host = senderHost.replace(/[^a-z0-9]/g, "");
    if (name.length > 3 && !host.includes(name.slice(0, Math.min(6, name.length)))) add(indicators, "Display name does not match sender domain", "The supplied display name is not clearly reflected in the sender domain. Verify through a known channel.", 20);
  }
  return result(indicators, indicators.some((item) => item.title === "Unusual sender identifier" || item.title === "Sender domain not verified") ? ["Verify an unfamiliar sender using a separate trusted channel before relying on the message.", "This local scan does not check domain registration, mail records, or sender reputation.", ...(indicators.some((item) => item.points > 0) ? ["Do not reply, open attachments, or use links until you are confident the message is legitimate."] : [])] : indicators.length ? ["Do not reply, open attachments, or use links in this message.", "Contact the organization using a phone number or website you already trust.", "Report the message to your mail provider or security team."] : ["No strong phishing patterns were found by these local rules.", "Confirm the sender and context independently before sharing sensitive information."]);
}

const disposableEmailDomains = new Set(["10minutemail.com", "discard.email", "guerrillamail.com", "mailinator.com", "sharklasers.com", "temp-mail.org", "tempmail.com", "yopmail.com"]);
const commonMailProviders = ["gmail", "yahoo", "outlook", "hotmail", "icloud"];

export function analyzeEmailAddress(raw: string): Analysis {
  const address = raw.trim();
  if (!address) return result([{ title: "Email address required", detail: "Enter one email address to analyze its format and local warning signs.", points: 0 }], ["Paste an address such as name@example.com."]);

  const at = address.lastIndexOf("@");
  const local = at > 0 ? address.slice(0, at) : "";
  const domain = at > 0 ? address.slice(at + 1).toLowerCase() : "";
  const labels = domain.split(".");
  const validLocal = local.length <= 64 && /^(?!\.)(?!.*\.\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(local);
  const validDomain = domain.length <= 253 && labels.length >= 2 && labels.every((label) => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)) && /^[a-z]{2,63}$/i.test(labels.at(-1) ?? "");
  const indicators: Indicator[] = [];
  if (address.length > 254 || at < 0 || address.indexOf("@") !== at || !validLocal || !validDomain) {
    add(indicators, "Invalid email address format", "This address does not match the supported email format rules. Correct spelling and punctuation before using it.", 35);
    return result(indicators, ["Check for one @ sign, a valid domain with a suffix, and no spaces or consecutive dots.", "Format validation cannot prove that a mailbox exists or can receive email."]);
  }

  const host = domain.startsWith("www.") ? domain.slice(4) : domain;
  const domainBase = labels.at(-2) ?? host;
  const tld = labels.at(-1) ?? "";
  if (disposableEmailDomains.has(host)) add(indicators, "Temporary email provider", `The domain ${host} is commonly used for temporary inboxes. This does not prove misuse, but it is unsuitable for verifying a lasting identity.`, 35);
  const providerLookalike = commonMailProviders.find((provider) => domainBase !== provider && editDistance(domainBase, provider) === 1);
  if (providerLookalike) add(indicators, "Possible email-provider typo", `The domain label “${domainBase}” closely resembles ${providerLookalike}. Check the spelling; lookalike domains can be used to imitate familiar mail services.`, 40);
  if (/^[a-z]{5,}\d{3,}$/i.test(local)) add(indicators, "Unusual sender identifier", "The name before @ is followed by several digits. This pattern is sometimes used by generated or throwaway accounts, though legitimate addresses can look the same.", 30);
  if (/[\u0080-\uFFFF]/.test(address) || tld.startsWith("xn--")) add(indicators, "Internationalized email address", "This address contains non-ASCII or punycode characters. Check the exact spelling carefully for lookalikes.", 20);
  add(indicators, "Mailbox not verified", "This detector checks the address locally. It does not query DNS, check mail delivery, domain ownership, or reputation.", 0);
  return result(indicators, indicators.some((item) => item.points > 0) ? ["Check the address character by character, especially the part after @.", "Do not treat a valid format as proof that the person or mailbox is genuine.", "Verify the sender through a separate trusted channel before sharing information."] : ["The address format looks valid, but that does not confirm the mailbox exists or belongs to the claimed person.", "Verify the sender independently before trusting a message."]);
}

const shorteners = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]);
const brands = ["google", "microsoft", "apple", "paypal", "amazon", "facebook", "instagram", "netflix", "bankofamerica"];
const brandLookalikes: Record<string, { brand: string; explanation: string }> = {
  netmirror: { brand: "Netflix", explanation: "The registered domain label “netmirror” resembles the name used by Netflix mirror sites. The scan did not visit the site or verify who operates it." },
};
const unusualTlds = new Set(["zip", "mov", "click", "top", "xyz", "work", "country", "gq", "tk"]);

function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0]; row[0] = i;
    for (let j = 1; j <= b.length; j++) { const temp = row[j]; row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1)); previous = temp; }
  }
  return row[b.length];
}

export function analyzeUrl(raw: string): Analysis & { normalized?: string; domain?: string; urlError?: string; facts: string[] } {
  const facts: string[] = [];
  if (!raw.trim()) return { ...result([], ["Enter a URL to analyze."]), facts, urlError: "Enter a URL." };
  if (raw.length > 2048) return { ...result([{ title: "Input too long", detail: "URLs are limited to 2,048 characters for analysis.", points: 0 }], ["Check that you pasted only the URL."]), facts, urlError: "URL exceeds 2,048 characters." };
  let url: URL;
  try { url = new URL(/^https?:\/\//i.test(raw.trim()) ? raw.trim() : `https://${raw.trim()}`); }
  catch { return { ...result([{ title: "Invalid URL", detail: "The input could not be parsed as a web address.", points: 0 }], ["Enter a valid hostname such as example.com."]), facts, urlError: "Invalid URL format." }; }
  if (!/^https?:$/.test(url.protocol)) return { ...result([{ title: "Unsupported protocol", detail: "Only HTTP and HTTPS web addresses are analyzed.", points: 0 }], ["Enter an HTTP or HTTPS URL."]), facts, urlError: "Only HTTP and HTTPS URLs are supported." };
  const indicators: Indicator[] = [];
  const hostname = url.hostname.toLowerCase();
  const unicode = /[^\x00-\x7F]/.test(raw) || hostname.startsWith("xn--");
  facts.push(`Scheme: ${url.protocol.slice(0, -1).toUpperCase()}`, `Host: ${hostname}`, `Subdomains: ${Math.max(0, hostname.split(".").length - 2)}`, `Path/query length: ${url.pathname.length + url.search.length} characters`);
  if (url.protocol === "http:") add(indicators, "No HTTPS transport", "The connection is not encrypted in transit; this alone does not prove a site is malicious.", 10);
  if (raw.length > 100) add(indicators, "Unusually long URL", `${raw.length} characters can hide the destination or carry tracking/redirect data.`, 10);
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith("[")) add(indicators, "IP address used as host", "A raw IP address instead of a recognizable domain is unusual for public login pages.", 28);
  if (unicode || hostname.startsWith("xn--")) add(indicators, "Internationalized domain name", "Unicode or punycode can create lookalike characters. Verify the domain in its ASCII form.", 24);
  const labels = hostname.split(".");
  if (labels.length > 4) add(indicators, "Many subdomains", `${labels.length - 2} subdomain labels may obscure the registered domain.`, 12);
  if (shorteners.has(hostname)) add(indicators, "URL shortener", "The final destination is hidden until expanded with a trusted tool.", 22);
  const tld = labels.at(-1) ?? "";
  if (unusualTlds.has(tld)) add(indicators, "Unusual top-level domain", `“.${tld}” is sometimes used in low-cost or disposable domains; this is not proof of abuse.`, 10);
  if (url.username || url.password) add(indicators, "Embedded user information", "Credentials embedded before the host can disguise the actual destination.", 26);
  if (/%(?:2f|5c|40|2e)/i.test(raw) || /\\\\|%[0-9a-f]{2}/i.test(raw)) add(indicators, "Encoded or escaped URL characters", "Encoded delimiters or escaped characters can make a URL harder to read.", 12);
  if (labels.slice(0, -2).some((label) => brands.some((brand) => label === brand || label.startsWith(`${brand}-`)))) add(indicators, "Brand appears only in a subdomain", "A familiar brand appears before the registered-domain label; inspect the actual hostname owner.", 20);
  const registrableGuess = labels.length >= 2 ? labels[labels.length - 2] : hostname;
  const lookalike = brandLookalikes[registrableGuess];
  if (lookalike) add(indicators, `Possible ${lookalike.brand} brand impersonation`, lookalike.explanation, 35);
  for (const brand of brands) if (registrableGuess !== brand && registrableGuess.includes(brand) && !lookalike) {
    add(indicators, "Brand name embedded in another domain", `The registered domain label “${registrableGuess}” contains the name ${brand}, but it is not that brand’s exact domain. This is a warning sign, not proof of impersonation.`, 30);
    break;
  }
  for (const brand of brands) if (registrableGuess !== brand && registrableGuess.length >= 4 && editDistance(registrableGuess, brand) === 1) { add(indicators, "Possible misspelled brand domain", `The domain label “${registrableGuess}” resembles ${brand}.`, 30); break; }
  if (/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/.test(raw)) add(indicators, "Invisible or directional characters", "Hidden Unicode formatting characters can disguise text.", 24);
  return { ...result(indicators, indicators.length ? ["Do not sign in or provide information on this site.", "Compare the registered domain with the organization’s official domain using a trusted source.", "A padlock or HTTPS does not mean the site is legitimate."] : ["No strong URL warning signs were found by these local rules.", "Heuristic analysis is not a reputation or malware scan; verify the domain independently."]), normalized: url.href, domain: hostname, facts };
}

export function analyzeHtml(html: string): Analysis {
  const indicators: Indicator[] = [];
  if (!html.trim()) return result([{ title: "Empty snippet", detail: "Paste a small HTML snippet to analyze its text patterns.", points: 0 }], ["Only paste code you are comfortable sharing locally in this browser."]);
  if (html.length > 50000) return result([{ title: "Snippet too long", detail: "Analysis is limited to 50,000 characters.", points: 0 }], ["Paste a smaller excerpt. Never paste live credentials or sensitive personal data."]);
  if (/<form\b[^>]*>/i.test(html) && /(password|type\s*=\s*["']?password|autocomplete\s*=\s*["']?current-password)/i.test(html)) add(indicators, "Credential collection form", "The snippet includes a form and password field. This does not establish who operates it.", 25);
  const action = html.match(/<form\b[^>]*action\s*=\s*["']([^"']+)["']/i)?.[1];
  const formHost = action && /^https?:\/\//i.test(action) ? (() => { try { return new URL(action).hostname; } catch { return ""; } })() : "";
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/<[^>]+>/g, "").trim().toLowerCase() ?? "";
  const pageHost = html.match(/<!--\s*page-host:\s*([^\s]+)\s*-->/i)?.[1]?.toLowerCase();
  if (formHost && pageHost && formHost !== pageHost && !formHost.endsWith(`.${pageHost}`)) add(indicators, "Form posts to a different host", "The form destination differs from the optional page-host hint. Confirm the intended destination before trusting the page.", 30);
  if (/<script\b[^>]*\bsrc\s*=/i.test(html)) add(indicators, "External script included", "External scripts can change page behavior; inspect source and ownership carefully.", 12);
  if (/(paypal|microsoft|google|apple|bank|university)/i.test(title)) {
    if (formHost && !formHost.includes(title.split(/\s+/)[0]) || /<!--\s*brand\s*:\s*([^>]+)-->/i.test(html)) add(indicators, "Possible brand impersonation", "A recognizable organization name appears alongside an unrelated destination or brand cue; this is not brand verification.", 18);
    else if (!formHost) add(indicators, "Recognizable organization in page title", "The title uses an organization name, but a static snippet cannot verify who owns the page.", 8);
  }
  if (!indicators.length) add(indicators, "No strong patterns found", "Static text checks found no obvious credential form or suspicious destination.", 0);
  return result(indicators, ["HTML was treated only as text and was never rendered or executed.", "A snippet cannot prove that a real website is safe or malicious.", "Do not paste real passwords, OTPs, or private user data."]);
}
