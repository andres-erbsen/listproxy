package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"rsc.io/letsencrypt"
	"strings"

	"gopkg.in/ldap.v2"
)

// nfsgroup MUST match [a-z0-9-] (no LDAP quoting is done)
func getMoiraNFSGroupMembers(nfsgroup string) ([]string, error) {
	l, err := ldap.Dial("tcp", "ldap.mit.edu:389")
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// ldapsearch -LLL -x -H ldap://ldap.mit.edu:389 -b "ou=lists,ou=moira,dc=mit,dc=edu" "cn=${nfsgroup}" member
	sr, err := l.Search(ldap.NewSearchRequest(
		"ou=lists,ou=moira,dc=mit,dc=edu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases /*sizelimit*/, 0 /*timelimit*/, 0 /*typesonly*/, false,
		"(cn="+nfsgroup+")",
		[]string{"member"},
		/*"control"*/ nil,
	))
	if err != nil {
		return nil, err
	}
	if l := len(sr.Entries); l != 1 {
		return nil, fmt.Errorf("expected exactly one list, found %d", l)
	}
	return sr.Entries[0].GetAttributeValues("member"), nil
}

var deprecatedRSAIncEmailAddressForUseInSignatures = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func getMITCertEmailAddress(chains [][]*x509.Certificate) (string, error) {
	if len(chains) == 0 {
		return "", errors.New("no verified certificate chains")
	}
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		cert := chain[0] // leaf
		for _, name := range cert.Subject.Names {
			if !name.Type.Equal(deprecatedRSAIncEmailAddressForUseInSignatures) {
				continue
			}
			if email, ok := name.Value.(string); ok {
				return email, nil
			}
		}
	}
	return "", errors.New("no MIT certificate email address found")
}

func main() {
	dst, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(dst)

	var letsEncryptManager letsencrypt.Manager
	if err := letsEncryptManager.CacheFile("letsencrypt.cache"); err != nil {
		log.Fatal(err)
	}

	clientCAsPEM, err := ioutil.ReadFile("client-certificate-authorities.pem")
	if err != nil {
		log.Fatalf("error reading client CAs file: %s", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAsPEM) {
		log.Fatalf("failed to parse client CA certificate")
	}
	nfsgroup := "andreser-test-nfsgroup-empty"
	authorize := func(req *http.Request) error {
		email, err := getMITCertEmailAddress(req.TLS.VerifiedChains)
		if err != nil {
			return err
		}
		email = strings.ToLower(email)

		members, err := getMoiraNFSGroupMembers(nfsgroup)
		if err != nil {
			return err
		}

		// USER entries -- MIT kerberos accounts
		at_mit_edu := "@mit.edu"
		if strings.HasSuffix(email, at_mit_edu) && strings.Count(email, "@") == 1 {
			kerberos := strings.TrimSuffix(email, at_mit_edu)
			for _, member := range members {
				if member == "uid="+kerberos+",OU=users,OU=moira,dc=MIT,dc=EDU" {
					return nil
				}
			}
		}

		// STRING entries -- full email addresses
		for _, member := range members {
			if member == "cn="+email+",OU=strings,OU=moira,dc=MIT,dc=EDU" {
				return nil
			}
		}

		return fmt.Errorf("authenticated as %q, but not authorized because not on %q", email, nfsgroup)
	}

	srv := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: letsEncryptManager.GetCertificate,

			ClientCAs:  clientCAs,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if err := authorize(req); err == nil {
				reverseProxy.ServeHTTP(w, req)
			} else {
				http.Error(w, fmt.Sprint(err), 401)
			}
		}),
	}

	go func() { log.Fatal(http.ListenAndServe(":http", http.HandlerFunc(letsencrypt.RedirectHTTP))) }()
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
