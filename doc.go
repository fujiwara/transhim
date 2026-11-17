// Package transhim is a framework for building servers that speak the
// HashiCorp Vault Transit HTTP API while delegating the actual cryptography
// to a user-supplied [Backend], typically a cloud KMS.
//
// A minimal server:
//
//	srv, err := transhim.NewServer(
//		transhim.Mount("/v1/transit", "rgw-kms", backend),
//		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
//	)
//	if err != nil {
//		return err
//	}
//	return http.ListenAndServe(addr, srv)
//
// The mount ID ("rgw-kms" above) is bound into every ciphertext. Changing it
// makes all existing ciphertexts of that mount undecryptable. The prefix is
// used for HTTP routing only and can change freely.
//
// The server passes data keys in plaintext to its clients, as the Transit
// datakey API requires. Serve it over TLS.
package transhim
