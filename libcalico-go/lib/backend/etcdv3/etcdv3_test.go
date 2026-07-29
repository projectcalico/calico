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
MIIDFTCCAf2gAwIBAgIUQDkKj7nwdh1H50yYX44vJ3CExC4wDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHZXRjZC1jYTAeFw0yNjA3MjkxNzQxNTJaFw0zNjA3MjYx
NzQxNTJaMBIxEDAOBgNVBAMMB2V0Y2QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCioaf8ercDEfvLoojcqUoH3bkS7K9GcbTOoqOHzNmcJ77FLi4e
5wjfszhljx86pbWBhQWwFQuN6H4urFUypx+D+fG6P7I1R/exin8m/cvZbTt3w9r7
TDubl2CQbjS5EMZESvyBYba1p46NXDVFbRw3XtfiO1KCHFR539ZPUmHLuqkO/T75
tXCRjLMiK8eW79Ke2t9g5I5qZoHfufrz3Sf0ODGEqm3d7rDubo1+4Fa/HgNkw8qZ
xy00y+358ve7xXRpn8fNUWc065JqSSKeLLTRuoFGpypFs6EDSP6s23YLLoboIVGu
bqYOT7Fr2J5YQ2I9NW72256sxmjBDeUcs06NAgMBAAGjYzBhMB0GA1UdDgQWBBTc
8TcxtQDcrBF3FyRIf0RlEURrczAfBgNVHSMEGDAWgBTc8TcxtQDcrBF3FyRIf0Rl
EURrczAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0B
AQsFAAOCAQEAZLuXMwDRbuUbv3vjeXISLc6Hp/3OHhyYbYpjR+DzjOAXqjZ62ntk
IMSQ0fTVI2vPYUIs7qlw7piMvnHr/ULXOPoHYgfY+eC88+nhY0Rq4rt/4zBJ1PvD
FOUpq8lp6y+VlxjBfoPTcWucbcqPqpX6PBaXQ4bSSU4i/MUAWqKN75JazMtcgBri
yuWb8gV9u57Ao9xpc/ob4oApDin9Rl5A7z2CmL/Sbttr/Oihfey2tQzjPRVfScE8
oSJtx+x/s+2jtMyH6wjSoVirp3I7WU+WixpENSVijXNQzqNucUkbQ+Wcpx6cjVNG
zmkkSbak1uPF04Zfmn5soh9yzjJjzXo4VQ==
-----END CERTIFICATE-----`
	etcdCertValue = `-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIUEbu5g3K1eYBCcQW0J58BtTrFLX8wDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHZXRjZC1jYTAeFw0yNjA3MjkxNzQxNTJaFw0zNjA3MjYx
NzQxNTJaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL39y9B4bACRFZpcc9O9ozeSSgFnl/pVoSB0y4alz285eyuW
otBBMC5btKtZdqrRhG4lFW9EazNGCNgorwobvKxxZ/civ3HfQKcb0Wb5aSvUMsVN
z37JuMSKjFz0gLnmlprR/RFkCjW/9NPpNqBYfmIIEH5Hu5NHDUZdhmVR8N8ii240
jsLXIW2Aa1BXsZb0qglqJu86W0NE+NiLt+IG3sWw7+QW2OwLy7UN+bTVnWiJZg/w
ygRnBEs7LnZl/kjsm6kGvwJ2XpoOEyI/8ax5Sj0KDbaxh0UxiH/EZDsaDLQT80Kk
kHSqJpuVhCRSJJQNAPlJrzbJ/POpWIx0+rEvbVsCAwEAAaOBqzCBqDAJBgNVHRME
AjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwLAYDVR0RBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAAB
MB0GA1UdDgQWBBQxwRLpLCvemNeWKIVOMZPX4Bx5szAfBgNVHSMEGDAWgBTc8Tcx
tQDcrBF3FyRIf0RlEURrczANBgkqhkiG9w0BAQsFAAOCAQEAdR25v8jyOIqj6zBV
FHJD9B+SIZdv/WK5BuO4RPTfoZjX9Vz4+k6jmiFDMeXmUrNa69G4jN7g5YjRxHlz
xN8Sl/zFT8Hn0dXq3r9OKAXjauEJU0mw/kZZNKRm13COikvdd/t9/gZk7VDwu1ZY
2ehGyzyO8sVh/yfNDiI604hXZ5FglLJU2ucuFiD6hHfZ22t9CccVZrQoRfD9mnzc
OqEqcVxihhExff6qOITqroTm37Fg94RjukQt6yE7ghYP98YbaDV5DDDhJD5VETDP
IRi5NhOI0kgyuX6ZUn6bA1dlHSKE5xqJsumKS2CJFtISmr+LU9rURnEuiuD2Ovlq
NRNV4A==
-----END CERTIFICATE-----`
	etcdKeyValue = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9/cvQeGwAkRWa
XHPTvaM3kkoBZ5f6VaEgdMuGpc9vOXsrlqLQQTAuW7SrWXaq0YRuJRVvRGszRgjY
KK8KG7yscWf3Ir9x30CnG9Fm+Wkr1DLFTc9+ybjEioxc9IC55paa0f0RZAo1v/TT
6TagWH5iCBB+R7uTRw1GXYZlUfDfIotuNI7C1yFtgGtQV7GW9KoJaibvOltDRPjY
i7fiBt7FsO/kFtjsC8u1Dfm01Z1oiWYP8MoEZwRLOy52Zf5I7JupBr8Cdl6aDhMi
P/GseUo9Cg22sYdFMYh/xGQ7Ggy0E/NCpJB0qiablYQkUiSUDQD5Sa82yfzzqViM
dPqxL21bAgMBAAECggEAB0gjbX2NZ3t9ZaRWfM6UuLa0Jxf2hLiPIOR+anjkxEFi
kvnxNTnSZBcitmXgPPgjyGmbx98fnAr6oCJLDIBMpnAASUIShAWc/5VQMiSsCcCB
I6ZxpffgS4l4i2rZm4ZsI59Ea6Fhx3abJnDBUGWj475QYi6opffqroA7fEWm4ukU
lJUHATevWY0nvctsCjJT+ulKTIvPbNyeb6YLMO45Gkmy6pS9UHYLArMAgcqVSH13
HCbUnOrrEocaYxM5uFAybJUasaME0AdBJwx2sgMVZRylQQlcxd8rxn0dS5fdVdLb
fQ7SaDjyVLe4hHRo1Sd1wx/bjawgvgLOor0xBE/pZQKBgQDuQ16vDU+tbA9C5oyc
p2RVpW6ApNk0p0rj5WDRDEWLm/q1mcJqcDRWxnBa+Mbn8Ek6KCjsw3yfvM+0kNI7
6fGiYbr8iF970NYHQdFyGvvJe0RidIqADm5CGfNPk3XmvtD1eeD8LSg5CXtcqDyY
XYrVFacbeoUIfWFdwBcpmWmhvQKBgQDMIoBOIPtcTX0wMrUIkx76shefGuRJpsI3
teIZEOSiyx5ZhDyyCOBK4iWBksExZODENZV5GCDeZ4De3Ko4EJ08f6dJmFZVsXt2
o3Bo7Zhm1Tv5mPUXSwQha1k2sO7yMt5D08X+rUDQcIPaULEUIWpqiv0P0Sk1RHjv
po5ApCvg9wKBgH67UOKVlvrsjlWMYeB1XPX9T4CXrnzGOxxrBotLFrbCmaD8jx+k
XQKG/H428z2tXpXThKki9efVOzmVCm4Z6o/vodDvDLLECwPDK4+g8KpjqaUgzgZ9
JoJ8YSHDkqPQfT8Eu/oGXu2vsHFBfzGgF9dtc/w2uAoi/qYqJWfYFQqVAoGAG1qs
Msv8otvHYMQKukFsr09aFvn1iWENOYXn7E/1M1Ngl8I+l+TUmXRAbmKJ/OJ1tBUy
GG4BSYw5GqQbMzQWvdqlQhllyEnmL3mrQIRGHdGJHeM/RIXK4eeOpuOCwXXLju87
4uq4erX5FTIm6Hmp1ukVDB+NFBQ+2G5LNaJKNvUCgYEAxN50ThK3juBaQwXb6IVm
5oav5EXYpeaZNP0Iaw6hqvfesBkrEeedF6a2wS7QGouSuxsjzxC2qrNuvNStMMOh
NIeq0ugSxMKyQR9ght/78iTXRro6e9xd8fhYsfQSZzh48FA1JbxJDpkI0lbDesWy
nzfor4a/6C+wzZUGuVMAq7o=
-----END PRIVATE KEY-----`
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
