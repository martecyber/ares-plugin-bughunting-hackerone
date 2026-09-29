package com.martecyber.plugins.bughunting.hackerone;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.integrations.tools.IntegrationClient;
import com.martecyber.plugins.bughunting.BugHuntingClient;
import com.martecyber.plugins.bughunting.CredentialField;
import com.martecyber.plugins.bughunting.PlatformApiException;
import com.martecyber.plugins.bughunting.ScopeImportItem;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * HackerOne Hacker API client for programme scope retrieval.
 *
 * Auth: HTTP Basic — Base64("api_username:api_token")
 *   Credentials map keys:
 *     api_username — HackerOne identifier shown on the API token settings page
 *     api_token    — HackerOne API token
 *
 * Test endpoint:
 *   GET /v1/hackers/programs?page[size]=1
 *   Returns 200 on valid credentials, 401 on invalid.
 *
 * Structured scopes endpoint (paginated via JSON:API links.next):
 *   GET /v1/hackers/programs/{handle}/structured_scopes?page[size]=100
 *
 * Response schema per item (JSON:API):
 *   data[].id                          — stable scope ID (upsert key)
 *   data[].attributes.asset_identifier — e.g. "*.example.com", "1.2.3.4"
 *   data[].attributes.asset_type       — URL | DOMAIN | CIDR | IP |
 *                                        IosAppStore | AndroidPlayStore |
 *                                        TESTFLIGHT | HARDWARE | SOURCE_CODE | OTHER
 *   data[].attributes.eligible_for_submission — false = out-of-scope (skip)
 *   data[].attributes.instruction      — optional notes
 *
 * Asset type → Ares scope kind mapping (see {@link #hackerOneAssetTypeToKind}):
 *   URL    → url / url_wildcard   (if identifier contains "*")
 *   DOMAIN → domain / domain_wildcard (if identifier starts with "*.")
 *   CIDR   → cidr
 *   IP     → ip / ip_wildcard (if identifier contains "*")
 *   rest   → other
 *
 * Ref: https://api.hackerone.com/getting-started-hacker-api/
 */
public class HackerOneClient implements BugHuntingClient, IntegrationClient {

    private static final Logger log = LoggerFactory.getLogger(HackerOneClient.class);
    private static final String BASE_URL  = "https://api.hackerone.com";
    private static final int    PAGE_SIZE = 100;

    private final HttpClient http;
    private final ObjectMapper objectMapper;

    public HackerOneClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    @Override public String platform() { return "hackerone"; }
    @Override public String label() { return "HackerOne"; }
    @Override public String supports()  { return "hackerone"; }

    // Unlike every other platform, HackerOne authenticates with a username+token pair, not a
    // bare token — see the class doc for why (HTTP Basic).
    @Override
    public List<CredentialField> credentialFields() {
        return List.of(
            new CredentialField("api_username", "API Username", "text", "your@email.com", true),
            new CredentialField("api_token", "API Token", "password", "API token", true));
    }

    @Override
    public String credentialHelpText() {
        return "Generate a token at HackerOne → Settings → API Token. The username is shown on that page.";
    }

    /** Validates credentials by fetching the first page of accessible programmes. */
    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        get("/v1/hackers/programs?page%5Bsize%5D=1", credentials);
    }

    /** Fetches all eligible (in-scope) structured scope entries, following pagination. */
    @Override
    public List<ScopeImportItem> fetchScope(String programHandle, Map<String, String> credentials)
            throws Exception {
        List<ScopeImportItem> items = new ArrayList<>();
        String path = "/v1/hackers/programs/" + programHandle
                    + "/structured_scopes?page%5Bsize%5D=" + PAGE_SIZE;

        while (path != null) {
            JsonNode root = get(path, credentials);
            JsonNode data = root.path("data");

            if (data.isArray()) {
                for (JsonNode entry : data) {
                    JsonNode attrs = entry.path("attributes");

                    String id              = entry.path("id").asText(null);
                    String value           = attrs.path("asset_identifier").asText("").trim();
                    String assetType       = attrs.path("asset_type").asText(null);
                    boolean inScope        = attrs.path("eligible_for_submission").asBoolean(true);
                    boolean bounty         = attrs.path("eligible_for_bounty").asBoolean(false);
                    String instr           = attrs.path("instruction").asText("").trim();
                    java.time.OffsetDateTime platformCreatedAt = parseDateTime(attrs.path("created_at").asText(null));
                    java.time.OffsetDateTime platformUpdatedAt = parseDateTime(attrs.path("updated_at").asText(null));

                    // Log full entry attributes to help diagnose unexpected entries
                    log.debug("H1 scope entry id={} value={} asset_type={} inScope={} bounty={} relationships={}",
                        id, value, assetType, inScope, bounty, entry.path("relationships"));

                    if (value.isEmpty()) continue;

                    // Build notes: instruction + bounty eligibility line
                    String bountyLine = bounty ? "Bounty: eligible" : "Bounty: not eligible";
                    String notes = instr.isEmpty() ? bountyLine : instr + "\n" + bountyLine;

                    String kind = hackerOneAssetTypeToKind(assetType, value);
                    // When unrecognised, surface the raw type in notes for visibility
                    if ("other".equals(kind) && assetType != null) {
                        String typeNote = "[H1 type: " + assetType + "]";
                        notes = notes.equals(bountyLine) ? typeNote + "\n" + notes
                                                         : notes + "\n" + typeNote;
                    }
                    items.add(new ScopeImportItem(kind, value, id, notes, inScope,
                        platformCreatedAt, platformUpdatedAt, null));
                }
            }

            // Follow JSON:API pagination via links.next (absolute URL)
            JsonNode next = root.path("links").path("next");
            if (!next.isMissingNode() && !next.isNull()) {
                String nextUrl = next.asText("");
                // Strip base URL to get just the path+query
                path = nextUrl.startsWith(BASE_URL)
                    ? nextUrl.substring(BASE_URL.length())
                    : null;
            } else {
                path = null;
            }
        }

        log.info("HackerOne fetchScope programme={} eligible_items={}", programHandle, items.size());
        return items;
    }

    private static java.time.OffsetDateTime parseDateTime(String s) {
        if (s == null || s.isBlank()) return null;
        try { return java.time.OffsetDateTime.parse(s); } catch (Exception e) { return null; }
    }

    // ── Asset type mapping ───────────────────────────────────────────────────

    /** Normalises "Android: .apk" → "ANDROIDAPK", "iOS: App Store" → "IOSAPPSTORE" (strips
     *  everything but A-Z0-9, uppercases) before matching — HackerOne sends human-readable
     *  display strings, not stable enum codes. */
    private static String hackerOneAssetTypeToKind(String assetType, String value) {
        if (assetType == null) return "other";
        String n = assetType.toUpperCase().replaceAll("[^A-Z0-9]", "");
        return switch (n) {
            case "DOMAIN"                           -> isDomainWildcard(value) ? "domain_wildcard" : "domain";
            case "WILDCARD"                         -> isDomainLike(value)    ? "domain_wildcard"  : "url_wildcard";
            case "URL"                              -> isWildcard(value)      ? "url_wildcard"     : "url";
            case "CIDR"                             -> "cidr";
            case "IP", "IPADDRESS"                  -> isWildcard(value)      ? "ip_wildcard"      : "ip";
            case "IOSAPPSTORE",
                 "TESTFLIGHT",
                 "IOSTESTFLIGHT",
                 "IOSIPA",
                 "IOSIPA2"                          -> "ios_app";
            case "ANDROIDPLAYSTORE",
                 "GOOGLEPLAY",
                 "GOOGLEPLAYSTORE",
                 "GOOGLEPLAYAPPID",
                 "ANDROIDAPK",
                 "OTHERAPK"                         -> "android_app";
            case "WINDOWSMICROSOFTSTORE",
                 "MICROSOFTSTORE",
                 "WINDOWSSTORE",
                 "WINDOWSAPPSTOHEAPPID",
                 "WINDOWSAPPSTOREAPPID",
                 "WINDOWSEXECUTABLE",
                 "EXECUTABLE"                       -> "windows_app";
            case "HARDWAREIOT",
                 "HARDWARE"                         -> "hardware";
            default                                 -> "other";
        };
    }

    private static boolean isWildcard(String value) {
        return value != null && value.contains("*");
    }

    private static boolean isDomainWildcard(String value) {
        return value != null && value.startsWith("*.");
    }

    /** Heuristic: a "Wildcard" asset is domain-like when it has no URL scheme. */
    private static boolean isDomainLike(String value) {
        if (value == null) return false;
        return !value.contains("://");
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private JsonNode get(String path, Map<String, String> credentials) throws Exception {
        String username = credentials.getOrDefault("api_username", "");
        String token    = credentials.getOrDefault("api_token", "");
        String basicAuth = Base64.getEncoder().encodeToString(
            (username + ":" + token).getBytes(java.nio.charset.StandardCharsets.UTF_8));

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + path))
            .timeout(Duration.ofSeconds(10))
            .header("Authorization", "Basic " + basicAuth)
            .header("Accept", "application/json")
            .GET()
            .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300)
            throw new PlatformApiException("HackerOne", resp.statusCode(), resp.body());
        return objectMapper.readTree(resp.body());
    }
}
