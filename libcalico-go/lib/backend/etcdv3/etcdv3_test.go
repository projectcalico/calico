package etcdv3_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/etcdv3"
)

var (
	etcdCACertWrongFormatValue = `-----BEGIN CERTIFICATE-----
MIIDvgYJKoZIhvcNAQcCoIIDrzCCA6sCAQExADALBgkqhkiG9w0BBwGgggORMIID
jTCCAvagAwIBAgIQUuSuRj0Dyvze/mcVMwwBCTANBgkqhkiG9w0BAQUFADCBzjEL
MAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2Fw
ZSBUb3duMR0wGwYDVQQKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMf
Q2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjEhMB8GA1UEAxMYVGhhd3Rl
IFByZW1pdW0gU2VydmVyIENBMSgwJgYJKoZIhvcNAQkBFhlwcmVtaXVtLXNlcnZl
ckB0aGF3dGUuY29tMB4XDTA2MTAyMDAzMzIyNVoXDTA3MTAyMDAzMzIyNVowgZEx
CzAJBgNVBAYTAkFVMREwDwYDVQQIEwhWaWN0b3JpYTESMBAGA1UEBxMJTWVsYm91
cm5lMS0wKwYDVQQKEyRDYXJlIEZvciBLaWRzIEludGVybmV0IFNlcnZpY2VzIFAv
TCAxCzAJBgNVBAsTAklTMR8wHQYDVQQDExZ3d3cuY2FyZWZvcmtpZHMuY29tLmF1
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw/gfqN/0OAf3uZku10cQSJw48
HUgfqRHZTRWHAvdxyORjWY/+7qozwx/Ja9VyxX/Z87hcY+EEXJ8WzB6Ojchl/D1K
9oWN9DnxDmiQgvPQ0F92nfxXeg71oIUS2EVChZoqHa25lv3VuKyk3eX0NFzKITwn
+qvYFcejBzTvUV5ewQIDAQABo4GmMIGjMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vY3JsLnRoYXd0ZS5jb20v
VGhhd3RlUHJlbWl1bVNlcnZlckNBLmNybDAyBbbqBgEFBQcBAQQmMCQwIgYIKwYB
BQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wDAYDVR0TAQH/BAIwADANBgkq
hkiG9w0BAQUFAAOBgQDKFdgfgF6/y/aRvkRKVtU+PqCfiQ2+bLNEPy2xCK7LVM0k
SaZ407kT4F1I4NlPEyoKRNMa3b6m0+fk8J3yvqiZKI1eJbaLTDEeG7BtgcdaM1ST
iNaH2zqWlIShVTKEc8ACo1HUTP2slfQ7Q7GIR3sGU2Z+fRD3GXwwAoyo5Mh1aEA
MQA=
-----END CERTIFICATE-----`
	etcdCACertValue = `-----BEGIN CERTIFICATE-----
MIICwjCCAaqgAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdldGNk
LWNhMB4XDTE5MDIxMTEyNDYyN1oXDTI5MDIwODEyNDYyN1owEjEQMA4GA1UEAxMH
ZXRjZC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM3wZhFy9lS3
lWGaBXm9supI0k+aY1EOqeap831jVSAARZQ8uP5NUBP57dJOxG7Qo1eOWmqwshpT
brcDNdX3k0eTiIRCQmo0MQyixaTbbwdAqugyRiIDnQ9PfKLyi+q4GIpge7VKenkh
EM68Ra0+Tgjq3HNQK4JPEB387fjhBL0IDRZwBBnDfOEP5mpSqshqkizEsTqX7kxT
aDiY94W3Rj9g4LhwnkZRaAgIKJTfLjo9BVc9cupiS2iv+I6EVqR8CqeNfC3x+sjh
jhcC4SFJggAh6ZuTrga1trmEAF/JbHrjZtcy8/sKlJLhiuM1lXmyfld3g8Cgv7EZ
Rh2kvPJFvfsCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMB
Af8wDQYJKoZIhvcNAQELBQADggEBAMYwmTnzvDlZNx3DriIhLMOMQUOPkTzT5PZZ
G433e9xKJouowyPDpsXWi98VywpUOYUVqWP3FO5LB5dpl3+ZV3IBl88hwTAFI66n
AUpbFgjHZkqRHosxYE0GfUT9vn+8R0IpN3X2czbRIMWOLBleQUyRkMZ2sAehRpPQ
Ue8shBiDSzRlDxH9d1rhN1AWqNSw4qgLMP7h/kza9y62q49/3YMADOi35Japiihj
uuM/kqlzIWY2Kl+3PQ0q/VXYazK53h7q6dexJ6k449RIG50lcciZ5z1vVJeq8Hn3
xFwj4AfoV1jeBbgi+2rlmvoY8zbOVSZOIz7XMcPbxkw/oTjVFh8=
-----END CERTIFICATE-----`
	etcdCertValue = `-----BEGIN CERTIFICATE-----
MIIDZjCCAk6gAwIBAgIIUfS5ybKbuFMwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AxMHZXRjZC1jYTAeFw0xOTAyMTExMjQ2MjdaFw0yMDAyMTExMjQ2MjdaMDoxODA2
BgNVBAMTL2lwLTE3Mi0yMC02My0xOC5hcC1ub3J0aGVhc3QtMi5jb21wdXRlLmlu
dGVybmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsFOw+ale1ucr
06KwBDYY9jlOb1w2k66mY+/g95Xu8lqF5kgluQbjxxYr1yy3dxLWjRhVPG8LKz5p
gIkT7A/PML2WmjFEfHiW4a4orpSu/ieQSp0+149qv9hUFq/qossq6ceanFmHbOCN
PrJbtwiiZIPAsgP5OICD9eODUp6ijBrHQNBucKuF2c2XYwiPZzcMghaiZYRzf60J
JVN4NFhRlmeTVTFKYR435qNBeDSTa8C7yzjPgvI8OEGfW/TqUMMv56g01O+2cy57
3lTrfLkFG9FxlLa4oAOujbBz421A6GURA5IQufpENo4/dvCzzzjQf0jkLB0HrFmc
mSlFzTM4WwIDAQABo4GXMIGUMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwYwYDVR0RBFwwWoIvaXAtMTcyLTIwLTYzLTE4LmFw
LW5vcnRoZWFzdC0yLmNvbXB1dGUuaW50ZXJuYWyCCWxvY2FsaG9zdIcErBQ/EocE
fwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQsFAAOCAQEAOqhVikh9
BZXQIZz9ovHID99ZyvdIBUuD8HGKuTyaC/p9CLgrIY0AvbPsckOq6N3m8w/GogLk
jIEpl3W8tmpm01eYO8U5A7HExn1GL7tIAt1MB0agD/DC715Atjfiy+KF/+FSxLWI
P8+PXCwgF78jk6Qb0qBSAN2FMlJ4DktDGDL3o2cQ+Vt4ig/bNBT30+oueLXkoeuI
sJIX8WdYo33+I211cv48DLKw6poYmbJDHSqB9gPXUmyG3d4L3UKSBTiHp1kBx4ZF
UOrbQaRX5fPdgMFtnp1z5GKgmmGKjDJl1yGwyOSt0r4DWYl/cneV0K1FG2bNjVX8
scsL24FNnEI8iQ==
-----END CERTIFICATE-----`
	etcdKeyValue = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsFOw+ale1ucr06KwBDYY9jlOb1w2k66mY+/g95Xu8lqF5kgl
uQbjxxYr1yy3dxLWjRhVPG8LKz5pgIkT7A/PML2WmjFEfHiW4a4orpSu/ieQSp0+
149qv9hUFq/qossq6ceanFmHbOCNPrJbtwiiZIPAsgP5OICD9eODUp6ijBrHQNBu
cKuF2c2XYwiPZzcMghaiZYRzf60JJVN4NFhRlmeTVTFKYR435qNBeDSTa8C7yzjP
gvI8OEGfW/TqUMMv56g01O+2cy573lTrfLkFG9FxlLa4oAOujbBz421A6GURA5IQ
ufpENo4/dvCzzzjQf0jkLB0HrFmcmSlFzTM4WwIDAQABAoIBAGMr7xG8TPcZtfCm
Q9Fai9eQi6jeeGO/ix4SQLl/vpDYkQ7f7TePxHSo56dyIw35rmpVETuYSPPdeoEs
l+PhUGrdduLqataHDHWJ+p+WSIXxwpn0ru+WXjfgeAr6jkFZe51ZAoCFakG2Wjq1
Hhhn5s4ZvDtjOLyqq42UlLvXNR0O0w4uD5QtnuPvYNIvhZwafKtHGyyxPEUW1fFu
fG3sDzHlXAwhIsGZTz3MJLddOrdGxmWL3/1IngzJC32oRX3quA4hLj4BujgNUSOG
T/pATwtldKSNRhR6IssTuYul60nxiHM3gIJ/rp6Hx5P3bv05VsFaBR6uzwSiGwHn
YxdQIsECgYEA43LjpsAk4+5WFbUr5fpdT7sS7iPsYiz2f0nZYnPHzUlFcNa1J4ge
tys0p6UNdfS7TNlSlg4bQRx0CttZJVS6iaujuV0aZnPD0/GedsZDEQRwjXli3jut
hL2az+DmjxsrLtjOALC0wxnJxHz3qDtSHxgWvdZtWVow6fKVytiWzuMCgYEAxnX9
r7L9dRk72x9YF+Jc1GD6KIUujK5zkNQVj6bH0hLtwSPM2NkxK0jeSjx76lhB7aag
GFVqXNTpqh/186s3zrSFofM8WZHaNyD44hwNmY5G3DP7zCfwi9fDJ7kT1A5sAtwe
aF2AZFDsVMeV2OaoaJlHfvp0YonvXF0NLlhZcikCgYAZQGwd2z89Pvy3tEGHauBp
Na/IWJyp2awUPbKwx4HrPLNE79F07hva4iUaZ6yy59TTl10f47kK5YnMmsWu61U6
a5/luHxx23BmW3DoZuKTRRbp3gwn+CAvmI1TfviZ8r48mT1lvjiTYI2SDv2/47Ye
VaJQuTmyrdy4XIJc3ub/WQKBgE7d/N6hxs+OI5dEsYFsV2+eykroAkOt4AciAR+B
K89z7j/etj1Gsp986bmep6/NOwXyPZTt/MK/acxNvzQCSr8+RgzB2K3PpGRcGgvh
EhZ/z/EaR2ouRQ2NxOQ4TITs5keMqhjXb3puHjziw83ae/p1T1BKv42ZOyH9aIuO
WJ1hAoGBAJSy89QqjjYHLi5mRxS4z8/SwwhLW1jQ4VQDq7KwZngZFRPdpXHpc06x
to3XutJax7SQw3540C2OGSjZdtQkvwEOUxgDTF8QjRBnAsfyyucdv3VWWsLMEdBD
2NMC/lNSvir6cPelq7oi7u+TeFDG9pAt4oMrRxmZfqRm9rNTKo5k
-----END RSA PRIVATE KEY-----`
)

var _ = Describe("RulesAPIToBackend", func() {
	It("should raise an error if specified certs files don't exist", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",
			EtcdCertFile:   "/fake/path",
			EtcdKeyFile:    "/fake/path",
			EtcdEndpoints:  "http://fake:2379",
		})
		Expect(err).To(HaveOccurred())
	})

	It("shouldn't create a client with empty certs", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/dev/null",
			EtcdCertFile:   "/dev/null",
			EtcdKeyFile:    "/dev/null",

			EtcdCACert: "",
			EtcdCert:   "",
			EtcdKey:    "",

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("should raise an error if conflicting endpoint discovery configuration provided", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdEndpoints:    "https://127.0.0.1:5007",
			EtcdDiscoverySrv: "example.com",
		})
		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing only inline Key and not Certificate", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACert:    "",
			EtcdCert:      "",
			EtcdKey:       etcdKeyValue,
			EtcdEndpoints: "https://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing only inline Certificate and not Key", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACert: "",
			EtcdCert:   etcdCertValue,
			EtcdKey:    "",

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing a mix of inline Certificate-Key and Certificate-Key Files as parameters", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",

			EtcdCACert: "",
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for not being able to decode inline CA certificate", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "",

			EtcdCACert: etcdCACertWrongFormatValue,
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})
	It("[Datastore] should raise an error for providing a mix of all inline Certificate-Key and Certificate-Key Files as parameters", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",
			EtcdCertFile:   "/fake/path",
			EtcdKeyFile:    "/fake/path",

			EtcdCACert: etcdCACertValue,
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should not raise any error while creating client object with inline Certificate-Key values as parameters", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACert: etcdCACertValue,
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "https://127.0.0.1:5007",
		})
		Expect(err).ToNot(HaveOccurred())
	})

	It("[Datastore] should discover etcd via SRV records", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdDiscoverySrv: "etcd.local",
		})
		Expect(err).ToNot(HaveOccurred())
	})

	It("[Datastore] should fail if SRV discovery finds no records", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdDiscoverySrv: "fake.local",
		})
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("failed to discover etcd endpoints through SRV discovery")))
	})
})
