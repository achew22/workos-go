package ssotest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/google/go-cmp/cmp"
	"github.com/workos-inc/workos-go/pkg/sso"
)

func setUp() (baseURL string, fakeWorkOSServer *Server, httpClient *http.Client, cleanup func()) {
	workOSServer, cleanup := New()
	workOSClient := workOSServer.Client()

	mux := http.NewServeMux()
	httpServer := httptest.NewServer(mux)

	callbackURL := httpServer.URL + "/callback"

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		opts := sso.GetAuthorizationURLOptions{
			Domain:      r.URL.Query().Get("domain"),
			RedirectURI: callbackURL,
		}
		u, err := workOSClient.GetAuthorizationURL(opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})

	mux.HandleFunc("/callback", func(rw http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(rw, fmt.Sprintf("No code provided in /callback"), 500)
			return
		}
		profile, err := workOSClient.GetProfile(r.Context(), sso.GetProfileOptions{
			Code: code,
		})
		if err != nil {
			http.Error(rw, fmt.Sprintf("sso.GetProfile(%q): %v", code, err), 500)
			return
		}

		profileJSON, err := json.Marshal(&profile)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Error encoding profile: %v", err), 500)
			return
		}

		fmt.Fprintf(rw, "%s", profileJSON)
	})

	return httpServer.URL, workOSServer, httpServer.Client(), cleanup
}

func TestLoginFlow_Negative(t *testing.T) {
	tests := map[string]struct {
		domain     string
		err        string // contains check
		statusCode int
		profiles   []sso.Profile
	}{
		// Don't insert any users in the fake and ensure it fails.
		"No registered profiles": {"escalator-corp.com", `please register a profile in the domain "escalator-corp.com"`, 400, nil},
		"Domain email mismatch": {"escalator-corp.com", `please register a profile in the domain "escalator-corp.com"`, 400, []sso.Profile{
			sso.Profile{Email: "foo@example.com"},
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			baseURL, fakeWorkOSServer, httpClient, cleanup := setUp()
			defer cleanup()

			for _, p := range test.profiles {
				fakeWorkOSServer.CreateFakeProfile(p)
			}

			loginURL := fmt.Sprintf("%s/login?domain=%s", baseURL, test.domain)
			res, err := httpClient.Get(loginURL)
			if err != nil {
				t.Fatalf("GET /login?domain=escalator-corp.com connection level error: %v", err)
			}
			if res.StatusCode != test.statusCode {
				t.Fatalf("GET /login?domain=escalator-corp.com should have status code %d, got %d", test.statusCode, res.StatusCode)
			}

			body, _ := ioutil.ReadAll(res.Body)
			if !strings.Contains(string(body), test.err) {
				t.Fatalf("Fake should warn you when you don't have an associated email with the requested domain.\nGot: %s", body)
			}
		})
	}
}

func TestLoginFlow_OneEmail(t *testing.T) {
	baseURL, fakeWorkOSServer, httpClient, cleanup := setUp()
	defer cleanup()

	want := sso.Profile{
		FirstName:      "Firstname",
		LastName:       "Lastname",
		Email:          "email@escalator-corp.com",
		ConnectionType: sso.GoogleOAuth,
		ID:             "identification",
		IdpID:          "idpidentification",
	}
	fakeWorkOSServer.CreateFakeProfile(want)

	loginURL := fmt.Sprintf("%s/login?domain=escalator-corp.com", baseURL)
	loginAndDiff(t, httpClient, loginURL, want)
}

// TestLoginFlow_MultipleProfiles ensures that in case there are multiple
func TestLoginFlow_MultipleProfiles(t *testing.T) {
	baseURL, fakeWorkOSServer, httpClient, cleanup := setUp()
	defer cleanup()

	want := map[string]sso.Profile{}
	for _, name := range []string{"first", "second", "third", "fourth"} {
		email := name + "@escalator-corp.com"
		want[email] = sso.Profile{
			FirstName:      name + "-Firstname",
			LastName:       name + "-Lastname",
			Email:          email,
			ConnectionType: sso.GoogleOAuth,
			ID:             "identification",
			IdpID:          "idpidentification",
		}
		fakeWorkOSServer.CreateFakeProfile(want[email])
	}

	loginURL := fmt.Sprintf("%s/login?domain=escalator-corp.com", baseURL)
	res, err := httpClient.Get(loginURL)
	if err != nil || res.StatusCode >= 400 {
		var body []byte
		if res != nil {
			body, _ = ioutil.ReadAll(res.Body)
		}
		t.Fatalf("GET /login?domain=escalator-corp.com:\nBody: %s\nError: %v", body, err)
	}

	n, err := html.Parse(res.Body)
	if err != nil {
		t.Errorf("html.Parse(res.Body): %v", err)
	}

	// Skip the <html> tag
	n = n.FirstChild

	type emailCode struct {
		email    string
		loginURL string
	}
	var parseA func(n *html.Node) []emailCode
	parseA = func(n *html.Node) []emailCode {
		var codes []emailCode
		if n.DataAtom == atom.A {
			var loginURL string
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					loginURL = attr.Val
				}
			}
			codes = append(codes, emailCode{
				email:    n.FirstChild.Data,
				loginURL: loginURL,
			})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			codes = append(codes, parseA(c)...)
		}
		return codes
	}

	for _, pair := range parseA(n) {
		loginAndDiff(t, httpClient, pair.loginURL, want[pair.email])
		generated := fakeWorkOSServer.LoginLinkForEmail(baseURL+"/callback", pair.email)
		if diff := cmp.Diff(pair.loginURL, generated); diff != "" {
			t.Errorf("HTML link and looked up link differed (-html,+generated):\n%s", diff)
		}
	}
}

func loginAndDiff(t *testing.T, httpClient *http.Client, loginURL string, want sso.Profile) {
	t.Helper()

	res, err := httpClient.Get(loginURL)
	if err != nil || res.StatusCode >= 400 {
		var body []byte
		if res != nil {
			body, _ = ioutil.ReadAll(res.Body)
		}
		t.Fatalf("GET /login?domain=escalator-corp.com:\nBody: %s\nError: %v", body, err)
	}

	body, _ := ioutil.ReadAll(res.Body)
	var got sso.Profile
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", body, err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Profile diff (-want,+got):\n%s\nBody: %s", diff, body)
	}
}

func TestDomainFromEmail(t *testing.T) {
	tests := []struct {
		email  string
		domain string
	}{
		{"user@foo-corp.com", "foo-corp.com"},
		{"user@weird.net@foo-corp.com", "foo-corp.com"},
	}

	for _, test := range tests {
		t.Run(test.email, func(t *testing.T) {
			got := domainFromEmail(test.email)
			if got != test.domain {
				t.Errorf("domainFromEmail(%q) = %q, want %q", test.email, got, test.domain)
			}
		})
	}

}
