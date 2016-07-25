package main

import "flag"

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
	l, err := ldap.DialTLS("tcp", "ldap.mit.edu:636", &tls.Config{ServerName: "ldap.mit.edu"})
	if err != nil {
		log.Print(err)
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
		log.Print(err)
		return nil, err
	}
	if l := len(sr.Entries); l != 1 {
		return nil, fmt.Errorf("expected exactly one list, found %d", l)
	}
	return sr.Entries[0].GetAttributeValues("member"), nil
}

var deprecatedRSAIncEmailAddressForUseInSignatures = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func getMITCertEmailAddressFullName(chains [][]*x509.Certificate) (string, string, error) {
	if len(chains) == 0 {
		return "", "", errors.New("no verified certificate chains")
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
				return email, cert.Subject.CommonName, nil
			}
		}
	}
	return "", "", errors.New("no MIT certificate email address found")
}

func run(register, listen, authenticate, authorize, proxy, state string) {
	dst, err := url.Parse(proxy)
	if err != nil {
		log.Fatalf("parse proxy url: %v", err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(dst)

	var letsEncryptManager letsencrypt.Manager
	if err := letsEncryptManager.CacheFile(state); err != nil {
		log.Fatal(err)
	}
	if register != "" && !letsEncryptManager.Registered() {
		letsEncryptManager.Register(register, func(terms string) bool {
			log.Printf("Agreeing to %s ...", terms)
			return true
		})
	}

	clientCAsPEM, err := ioutil.ReadFile(authenticate)
	if err != nil {
		log.Fatalf("error reading client CAs file: %s", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAsPEM) {
		log.Fatalf("failed to parse client CA certificate")
	}

	isAuthorized := func(email string) error {
		email = strings.ToLower(email)

		members, err := getMoiraNFSGroupMembers(authorize)
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

		return fmt.Errorf("authenticated as %q, but not authorized because not on moira list %q", email, authorize)
	}

	doAuthorize := func(req *http.Request) error {
		email, fullname, err := getMITCertEmailAddressFullName(req.TLS.VerifiedChains)
		if err != nil {
			return err
		}
		if err := isAuthorized(email); err != nil {
			return err
		}
		req.Header.Set("proxy-authenticated-full-name", fullname)
		req.Header.Set("proxy-authenticated-email", strings.ToLower(email))
		return nil
	}

	srv := &http.Server{
		Addr: listen + ":https",
		TLSConfig: &tls.Config{
			GetCertificate: letsEncryptManager.GetCertificate,

			ClientCAs:  clientCAs,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if err := doAuthorize(req); err == nil {
				reverseProxy.ServeHTTP(w, req)
			} else {
				http.Error(w, fmt.Sprint(err), 401)
			}
		}),
	}

	go func() { log.Fatal(http.ListenAndServe(listen+":http", http.HandlerFunc(letsencrypt.RedirectHTTP))) }()
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

var register = flag.String("register", "", "(optional) email address for letsencrypt registration")
var listen = flag.String("listen", "", "address to listen on (default:all)")
var authenticate = flag.String("authenticate", "", "path to a file containing PEM-format x509 certificates for the CAs trusted to authenticate clients")
var authorize = flag.String("authorize", "", "name of moira list whose members are authorized. The list MUST be marked as a NFS group (blanche listname -N)")
var proxy = flag.String("proxy", "", "URL to the service to be reverse-proxied")
var state = flag.String("state", "", "path at which the letsencrypt server state will be recorded")

func main() {
	flag.Parse()
	if *authenticate == "" || *authorize == "" || *proxy == "" || *state == "" {
		flag.Usage()
		log.Fatal("please specify the required arguments")
	}
	run(*register, *listen, *authenticate, *authorize, *proxy, *state)
}
