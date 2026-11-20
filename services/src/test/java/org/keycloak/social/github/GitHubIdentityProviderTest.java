/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.github;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for {@link org.keycloak.social.github.GitHubIdentityProvider}.
 *
 * @author Neon Ngo
 */
public class GitHubIdentityProviderTest {

    /**
     * Test constructor with empty config (i.e. to use default values).
     * This also tests GitHubIdentityProvider.getProfileEndpointForValidation(null).
     */
    @Test
    public void testGitHubIdentityProvider() {
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        GitHubIdentityProvider idp = new GitHubIdentityProvider(null, config);

        validateUrls(idp, GitHubIdentityProvider.DEFAULT_BASE_URL, GitHubIdentityProvider.DEFAULT_API_URL);
    }

    /**
     * Test constructor with config overrides of default base URL and API URL.
     */
    @Test
    public void testGitHubIdentityProviderOverrides() {
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        String baseUrl = "https://test.com";
        String apiUrl  = "https://api.test.com";
        config.getConfig().put(GitHubIdentityProvider.BASE_URL_KEY, baseUrl);
        config.getConfig().put(GitHubIdentityProvider.API_URL_KEY, apiUrl);
        GitHubIdentityProvider idp = new GitHubIdentityProvider(null, config);

        validateUrls(idp, baseUrl, apiUrl);
    }

    /**
     * Test that default scope does not include read:org when no organizations are configured.
     */
    @Test
    public void testDefaultScopeWithoutOrganizations() {
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        GitHubIdentityProvider idp = new GitHubIdentityProvider(null, config);

        assertEquals(GitHubIdentityProvider.DEFAULT_SCOPE, idp.getDefaultScopes());
    }

    /**
     * Test that read:org scope is added when organizations are configured.
     */
    @Test
    public void testDefaultScopeWithOrganizations() {
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        config.getConfig().put(GitHubIdentityProvider.ORGANIZATIONS_KEY, "my-org,another-org");
        GitHubIdentityProvider idp = new GitHubIdentityProvider(null, config);

        String scopes = idp.getDefaultScopes();
        assertTrue("Scope should contain user:email", scopes.contains("user:email"));
        assertTrue("Scope should contain read:org when organizations are configured", scopes.contains("read:org"));
    }

    /**
     * Test that read:org scope is not added when organizations value is blank.
     */
    @Test
    public void testDefaultScopeWithBlankOrganizations() {
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        config.getConfig().put(GitHubIdentityProvider.ORGANIZATIONS_KEY, "   ");
        GitHubIdentityProvider idp = new GitHubIdentityProvider(null, config);

        assertEquals(GitHubIdentityProvider.DEFAULT_SCOPE, idp.getDefaultScopes());
    }

    // --- Email domains: pick the verified work address, not the primary one

    private static JsonNode emails(String json) throws Exception {
        return new ObjectMapper().readTree(json);
    }

    private static final String PERSONAL_PRIMARY_AND_WORK = "["
            + "{\"email\":\"olli@example.com\",\"primary\":true,\"verified\":true},"
            + "{\"email\":\"olli.erinko@wunder.io\",\"primary\":false,\"verified\":true},"
            + "{\"email\":\"olli.erinko@mearra.com\",\"primary\":false,\"verified\":true}]";

    @Test
    public void testParseEmailDomains() {
        assertEquals(List.of("mearra.com", "wunder.io"), GitHubIdentityProvider.parseEmailDomains(" Mearra.com , wunder.io,, "));
        assertEquals(List.of(), GitHubIdentityProvider.parseEmailDomains("  "));
        assertEquals(List.of(), GitHubIdentityProvider.parseEmailDomains(null));
    }

    @Test
    public void testSelectEmailPrefersFirstConfiguredDomainOverPrimary() throws Exception {
        assertEquals("olli.erinko@mearra.com", GitHubIdentityProvider.selectEmail(emails(PERSONAL_PRIMARY_AND_WORK), List.of("mearra.com", "wunder.io")));
        assertEquals("olli.erinko@wunder.io", GitHubIdentityProvider.selectEmail(emails(PERSONAL_PRIMARY_AND_WORK), List.of("wunder.io", "mearra.com")));
    }

    @Test
    public void testSelectEmailIgnoresUnverifiedDomainAddress() throws Exception {
        // Anyone can add an unverified address to their GitHub account; trusting it would allow account takeover.
        String json = "[{\"email\":\"olli@example.com\",\"primary\":true,\"verified\":true},"
                + "{\"email\":\"ceo@mearra.com\",\"primary\":false,\"verified\":false}]";
        assertEquals("olli@example.com", GitHubIdentityProvider.selectEmail(emails(json), List.of("mearra.com")));
    }

    @Test
    public void testSelectEmailMatchesWholeDomainOnly() throws Exception {
        String json = "[{\"email\":\"a@notmearra.com\",\"primary\":false,\"verified\":true},"
                + "{\"email\":\"b@mearra.com.evil.io\",\"primary\":false,\"verified\":true},"
                + "{\"email\":\"c@sub.mearra.com\",\"primary\":false,\"verified\":true},"
                + "{\"email\":\"d@MEARRA.com\",\"primary\":false,\"verified\":true}]";
        assertEquals("d@MEARRA.com", GitHubIdentityProvider.selectEmail(emails(json), List.of("mearra.com")));
    }

    @Test
    public void testSelectEmailFallsBackToVerifiedPrimary() throws Exception {
        String json = "[{\"email\":\"olli@example.com\",\"primary\":true,\"verified\":true}]";
        assertEquals("olli@example.com", GitHubIdentityProvider.selectEmail(emails(json), List.of("mearra.com")));
    }

    @Test
    public void testSelectEmailReturnsNullForUnverifiedPrimaryAndNoMatch() throws Exception {
        String json = "[{\"email\":\"olli@example.com\",\"primary\":true,\"verified\":false}]";
        assertNull(GitHubIdentityProvider.selectEmail(emails(json), List.of("mearra.com")));
        assertNull(GitHubIdentityProvider.selectEmail(emails("{}"), List.of("mearra.com")));
    }

    // --- Teams: GitHub team slugs in the allowed organizations become the github_teams attribute

    private static final String API = GitHubIdentityProvider.DEFAULT_API_URL;
    private static final String FIRST_PAGE = API + GitHubIdentityProvider.TEAMS_FRAGMENT + "?per_page=100";
    private static final String SECOND_PAGE = API + GitHubIdentityProvider.TEAMS_FRAGMENT + "?per_page=100&page=2";

    private static String team(String org, String slug) {
        return "{\"slug\":\"" + slug + "\",\"name\":\"" + slug.toUpperCase() + "\",\"organization\":{\"login\":\"" + org + "\"}}";
    }

    private static GitHubIdentityProvider.TeamsPage page(String json, String link) throws Exception {
        return new GitHubIdentityProvider.TeamsPage(200, emails(json), link);
    }

    /** Serves pages from a map and records the URLs asked for, like GitHub would for one access token. */
    private static GitHubIdentityProvider.TeamsPageFetcher fetcher(Map<String, GitHubIdentityProvider.TeamsPage> pages, List<String> asked) {
        return url -> {
            asked.add(url);
            GitHubIdentityProvider.TeamsPage page = pages.get(url);
            if (page == null) {
                throw new IOException("unexpected URL " + url);
            }
            return page;
        };
    }

    @Test
    public void testCollectTeamsFollowsNextLinkAcrossPages() throws Exception {
        Map<String, GitHubIdentityProvider.TeamsPage> pages = new HashMap<>();
        pages.put(FIRST_PAGE, page("[" + team("wunderio", "silta-admins") + "," + team("wunderio", "developers") + "]",
                "<" + SECOND_PAGE + ">; rel=\"next\", <" + SECOND_PAGE + ">; rel=\"last\""));
        pages.put(SECOND_PAGE, page("[" + team("wunderio", "client-x") + "]",
                "<" + FIRST_PAGE + ">; rel=\"prev\", <" + FIRST_PAGE + ">; rel=\"first\""));
        List<String> asked = new ArrayList<>();

        List<String> teams = GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(pages, asked));

        assertEquals(List.of("client-x", "developers", "silta-admins"), teams);
        assertEquals(List.of(FIRST_PAGE, SECOND_PAGE), asked);
    }

    @Test
    public void testCollectTeamsKeepsOnlyAllowedOrganizations() throws Exception {
        Map<String, GitHubIdentityProvider.TeamsPage> pages = new HashMap<>();
        pages.put(FIRST_PAGE, page("[" + team("WunderIO", "silta-admins") + "," + team("other-org", "admins") + ","
                + team("mearra", "developers") + "," + team("wunderio", "silta-admins") + ","
                + "{\"slug\":\"no-org\"},{\"organization\":{\"login\":\"wunderio\"}}]", null));

        List<String> teams = GitHubIdentityProvider.collectTeams(API, List.of("wunderio", "mearra"), fetcher(pages, new ArrayList<>()));

        // Organization logins are case-insensitive on GitHub; duplicates and teams without a slug are dropped.
        assertEquals(List.of("developers", "silta-admins"), teams);
    }

    @Test
    public void testCollectTeamsReturnsNoTeamsOnApiError() throws Exception {
        // A failed page must not leave a partial list: no groups is the safe outcome (ArgoCD shows nothing).
        Map<String, GitHubIdentityProvider.TeamsPage> pages = new HashMap<>();
        pages.put(FIRST_PAGE, page("[" + team("wunderio", "silta-admins") + "]", "<" + SECOND_PAGE + ">; rel=\"next\""));
        pages.put(SECOND_PAGE, new GitHubIdentityProvider.TeamsPage(403, emails("{\"message\":\"rate limited\"}"), null));
        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(pages, new ArrayList<>())));

        // An error status counts even if the body happens to be a list.
        pages.put(SECOND_PAGE, new GitHubIdentityProvider.TeamsPage(500, emails("[" + team("wunderio", "developers") + "]"), null));
        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(pages, new ArrayList<>())));

        // The HTTP call itself failing (timeout, DNS) is handled the same way.
        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(new HashMap<>(), new ArrayList<>())));

        // So is a body that is not a list of teams.
        pages.put(FIRST_PAGE, page("{\"message\":\"Bad credentials\"}", null));
        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(pages, new ArrayList<>())));
    }

    @Test
    public void testCollectTeamsDoesNotSendTokenOffApiHost() throws Exception {
        // The access token goes with every page request, so a next link must stay on the configured API URL.
        Map<String, GitHubIdentityProvider.TeamsPage> pages = new HashMap<>();
        pages.put(FIRST_PAGE, page("[" + team("wunderio", "silta-admins") + "]",
                "<https://api.github.com.evil.io/user/teams?page=2>; rel=\"next\""));
        List<String> asked = new ArrayList<>();

        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of("wunderio"), fetcher(pages, asked)));
        assertEquals(List.of(FIRST_PAGE), asked);
    }

    @Test
    public void testCollectTeamsWithoutOrganizationsAsksNothing() throws Exception {
        List<String> asked = new ArrayList<>();
        assertEquals(List.of(), GitHubIdentityProvider.collectTeams(API, List.of(), fetcher(new HashMap<>(), asked)));
        assertEquals(List.of(), asked);
    }

    @Test
    public void testNextLink() {
        assertEquals(SECOND_PAGE, GitHubIdentityProvider.nextLink("<" + FIRST_PAGE + ">; rel=\"prev\", <" + SECOND_PAGE + ">; rel=\"next\""));
        assertNull(GitHubIdentityProvider.nextLink("<" + FIRST_PAGE + ">; rel=\"prev\""));
        assertNull(GitHubIdentityProvider.nextLink(null));
    }

    @Test
    public void testStoreTeamsReplacesAttributeOnEveryLogin() {
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put(GitHubIdentityProvider.TEAMS_ATTRIBUTE, List.of("removed-team"));
        UserModel user = user(attributes);
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        config.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("1", config);

        context.getContextData().put(GitHubIdentityProvider.TEAMS_CONTEXT_KEY, new ArrayList<>(List.of("developers", "silta-admins")));
        GitHubIdentityProvider.storeTeams(user, context);
        assertEquals(List.of("developers", "silta-admins"), attributes.get(GitHubIdentityProvider.TEAMS_ATTRIBUTE));

        // No teams (left every team, or GitHub failed): the attribute goes, so the token has no groups.
        context.getContextData().put(GitHubIdentityProvider.TEAMS_CONTEXT_KEY, new ArrayList<>());
        GitHubIdentityProvider.storeTeams(user, context);
        assertFalse(attributes.containsKey(GitHubIdentityProvider.TEAMS_ATTRIBUTE));
    }

    /** A UserModel that only supports setAttribute and removeAttribute, backed by {@code attributes}. */
    @SuppressWarnings("unchecked")
    private static UserModel user(Map<String, List<String>> attributes) {
        return (UserModel) Proxy.newProxyInstance(UserModel.class.getClassLoader(), new Class<?>[] { UserModel.class },
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "setAttribute":
                            attributes.put((String) args[0], new ArrayList<>((List<String>) args[1]));
                            return null;
                        case "removeAttribute":
                            attributes.remove((String) args[0]);
                            return null;
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
    }

    protected void validateUrls(GitHubIdentityProvider idp, String baseUrl, String apiUrl) {
        OAuth2IdentityProviderConfig config = idp.getConfig();
        assertEquals(baseUrl + GitHubIdentityProvider.AUTH_FRAGMENT, config.getAuthorizationUrl());
        assertEquals(baseUrl + GitHubIdentityProvider.TOKEN_FRAGMENT, config.getTokenUrl());
        assertEquals(apiUrl + GitHubIdentityProvider.EMAIL_FRAGMENT, config.getConfig().get(GitHubIdentityProvider.EMAIL_URL_KEY));
        assertEquals(apiUrl + GitHubIdentityProvider.PROFILE_FRAGMENT, config.getUserInfoUrl());
        assertEquals(apiUrl + GitHubIdentityProvider.PROFILE_FRAGMENT, idp.getProfileEndpointForValidation(null));
    }

}
