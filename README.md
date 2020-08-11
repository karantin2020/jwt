# jwt package

### Golang implementation of JSON Web Tokens (JWT) 
[![GoDoc](https://godoc.org/github.com/karantin2020/jwt?status.svg)](https://godoc.org/github.com/karantin2020/jwt)

Examples

Signed JWT  
```go
type TestClaims struct {
    Scope []string `json:"scope,omitempty"`
    jwt.StandardClaims
}
key1 := []byte("1234567890123456")
cl := TestClaims{
    Scope: []string{"read:repo", "write:settings"},
    StandardClaims: jwt.StandardClaims{
        Subject: "subject",
        Issuer:  "issuer",
    },
}
got, err := jwt.NewWithClaims(cl, &jwt.SignOpt{
    Algorithm: jose.HS256,
    Key:       key1,
})
if err != nil {
    panic("error = " + err.Error())
}
fmt.Printf("got: %s\n", got)
tok, err := jwt.ParseSigned(got)
if err != nil {
    panic("parse error = " + err.Error())
}
destCl := TestClaims{}
err = tok.Claims(key1, &destCl)
if err != nil {
    panic("parse error = " + err.Error())
}
fmt.Printf("got: %#v\n", destCl)
```

Signed and encrypted JWT  
```go
type TestClaims struct {
    Scope []string `json:"scope,omitempty"`
    jwt.StandardClaims
}
key1 := []byte("1234567890123456")
key2 := []byte("3214567890123459")
cl := TestClaims{
    Scope: []string{"read:repo", "write:settings"},
    StandardClaims: jwt.StandardClaims{
        Subject: "subject",
        Issuer:  "issuer",
    },
}
got, err := jwt.NewWithClaims(cl, &jwt.SignOpt{
    Algorithm: jose.HS256,
    Key:       key1,
}, &jwt.EncOpt{
    ContEnc: jose.A128GCM,
    Rcpt: jose.Recipient{
        Algorithm: jose.A256GCMKW,
        Key:       key2,
    },
})
if err != nil {
    panic("error = " + err.Error())
}
fmt.Printf("got: %s\n", got)
tok, err := jwt.ParseSignedAndEncrypted(got)
if err != nil {
    panic("parse error = " + err.Error())
}
nested, err := tok.Decrypt(key2)
if err != nil {
    panic(err)
}
destCl := TestClaims{}
err = nested.Claims(key1, &destCl)
if err != nil {
    panic("parse error = " + err.Error())
}
fmt.Printf("got: %#v\n", destCl)
```