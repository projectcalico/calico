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
MIIDFzCCAf+gAwIBAgIUbrj1JgSx5tiA5YZxFo2ajvy7mVswDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHZXRjZC1jYTAgFw0yNjA3MjkxNjIzNDdaGA8yMTI2MDcw
NTE2MjM0N1owEjEQMA4GA1UEAwwHZXRjZC1jYTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJOPtJz1kOnBn1yz4VfIyCKGTvm8tGTSHTy8iJ+fUVwFyVOk
60khGwm0iFL+mLSboIteEnF3u6cUePy7c9tzyGID6HI5tHxnZfO07VIjGfSzeugM
ZrTSkW9MuoMJnBvodqGytbYGqFMkUlbNPQKvWjt3DfKCM1BJ/wQJrfw/UrJHVJfe
Q455BbYjXOcT/BSwILKXEe7evDN71sxnvBWsZwbPALA87fDCwcDgC3bNzfzDzbVF
HgX+RdiRqK8MP1RuGZlxYmmlseny7PnDopHxQd2Ktq8gNi0+feq3aWFu0hszyjYZ
gGyJ5wYvGcEz8jCSHNPEOQKinwqq0rsuYXZM5ucCAwEAAaNjMGEwHQYDVR0OBBYE
FFCu6WgeXByYU9mYylT7iJZwa4gEMB8GA1UdIwQYMBaAFFCu6WgeXByYU9mYylT7
iJZwa4gEMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBKj4es7YGCWPrBeZLnY2+i50VrvknrNvagjjwXbXuoInXhqGWF
o4ROndstBcayq3TuHj4eh+6gyNJRvSLZzgBbMpbMSnnubyaV8qINuBVOZbvfOA68
Mv7HB9Y9rnODz11cuqt3fO5XWkPpubomqnn4jahU3ig/K3dRjmJCazgCiZBZMzEQ
EFASiI2xpIM/xBV5XoMJ2yuV3SyLhtEqr3sTcBnvG7RwiH0tU/uMPHUAYJzNSaWX
dhrtVaIsVTiCSOIE9OqB5s343iHK0paw2hioZI3L4D+DZo/uZIr9M8D8eVspvYlc
D7DfhsaptCwJm0BsAZsOvvzVSNKpkhmv53SI
-----END CERTIFICATE-----`
	etcdCertValue = `-----BEGIN CERTIFICATE-----
MIIDYjCCAkqgAwIBAgIUQYLY01IKwRRrFkskJ05aovoS06AwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHZXRjZC1jYTAgFw0yNjA3MjkxNjIzNDdaGA8yMTI2MDcw
NTE2MjM0N1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAlcgzMcwdw/r2VLQanegHD8tZL82lE/lD2Izw3zgS3xpa
2Jy5HtfOF8K5fyVjBMUs2Utjgl4Tqg2R1i62fe2SLLe2m5KZnbFpp/morz1pQzJ9
Y7DAbTyue2s5Kht/8zJaAvUsXuV+M10rOHKYjO9CBapYuHjk3O976dxQq4+WJoD3
bB4T2mouS6r+I0qK6wpoEjUIB4xMoRaJiOGvhCCiuCWk+RkcwXH4eMTbwhJ0NW1H
GWQjwJmiDe+qdr6Nwyh7iLjHYkpGbwzRErRhn5g7COy+ExToe1Zy0vB1nnhVy++3
+Kplp7bjwYQyqmOJSYs/tm277ZMXqQHGC38Wr/Gc9QIDAQABo4GrMIGoMAkGA1Ud
EwQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAA
AAEwHQYDVR0OBBYEFN3u0Xx6FOlAunpMpP5uK3vAtsZPMB8GA1UdIwQYMBaAFFCu
6WgeXByYU9mYylT7iJZwa4gEMA0GCSqGSIb3DQEBCwUAA4IBAQAZVg+z0HF+GUmf
fjPxV5vE0z4OsL3IH/u64Zremm9YNH6xuc2qtMR4VnWOD7a+Zwvvj0xN/1JBDnJQ
uJJKU/YQrfSf1IjWMxJIFxYuUren4ilt6k02Qb/r2oZLAnt0ltkjKA9Uq8VRxYWH
58p7iTheMZ9IYvM3MqjCRgCnuMpP5WaeCjXRR+F5/cCYX615Ew+fMab/GThrzL6w
3/Gezg62bMBrr6ukQYWAatxkV5o3mhnWYrZPwDJ1IcMF3gPfjXZ70ub8L6VpbTCs
iTEILpidMbjdEVI4ByilOXXzo5DFlPbfgZ4PGvuzvgYIDPT5nOkIjcL+m5QYBETw
OIlkDc0L
-----END CERTIFICATE-----`
	etcdKeyValue = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCVyDMxzB3D+vZU
tBqd6AcPy1kvzaUT+UPYjPDfOBLfGlrYnLke184Xwrl/JWMExSzZS2OCXhOqDZHW
LrZ97ZIst7abkpmdsWmn+aivPWlDMn1jsMBtPK57azkqG3/zMloC9Sxe5X4zXSs4
cpiM70IFqli4eOTc73vp3FCrj5YmgPdsHhPaai5Lqv4jSorrCmgSNQgHjEyhFomI
4a+EIKK4JaT5GRzBcfh4xNvCEnQ1bUcZZCPAmaIN76p2vo3DKHuIuMdiSkZvDNES
tGGfmDsI7L4TFOh7VnLS8HWeeFXL77f4qmWntuPBhDKqY4lJiz+2bbvtkxepAcYL
fxav8Zz1AgMBAAECggEAChDTce4F9RD1Q3F8FW8NpG/VvUrsZFh8yP2FxXaC/CfN
AaAcp7g4gyvEpAkK67vlfO/eTtlMKIIzcgmfHXzc9TDebnuOY8TTtSRnw+kUXR30
Q8IR2HV6w1QMGiqRcXJJjsfTtMfm8IQ7HpbC7ju4++D8B9+l/7v/X5K9AB6M6Gbp
hKeDPJSGLExT/gOEPN/tAqIDKeTP3coNYBICxtovCB18Z4Nd3eEcIExX0ypFT027
doxuRmi4Fx5kRHWk56Hs1WGb0sxMfiAm+QHC1DqfwNouBSR93F8i2vTdq1ShebWH
UkfEAAHbPb16D9dDNLv4C98UtYl2CGOHWqIJFigd8QKBgQDKJYHh27/xoIkqRMP1
Bb7HiyfwhjGPsEfTc0BPNpigfd56H7eLIUVqKNP2RNd1O2q/CCv38kNDnc+uJ0Qn
jlEYdO/az1oC0XxEysJFX0kfxTRWlVFSGr+50zYYHZgqzZCHY27dtX4lUnbe/d+z
wxgWHR6//uWd7hV+aEaekgBxRQKBgQC9r2iwEGDPPiHEY1A1eLUHtjRLfVhebCPt
sGlADRJ8PsCtjy63QyUwKyY0fvuy15jX8dZ1JA79mHNfnL8vMFxsk9qGOFeyRtF0
QFjFE+sSwCCwa5WjjPt/12tk6uTbu+tfYp1TYnw2nheVQBALhi2ZS++UppPPGLDN
m5zPd/s/8QKBgQChbOhWY7TZENjYT0eo8CiUktSXJ6KGW0BQZDXTzAaAC2PRZGif
Czeyed4iSIFCVet9l9n8y5LZeTlymlq7t9Oc0y0DMBhyLbWt/bi7y0bKvyF3jw/8
n+3BSCBni6KLc9LZuxa6qAePaFYS5utwUvh2GFUI/1WAE7NIWZ8jW/ZMfQKBgQCl
QdIaOlqtk7sFh2TVATHu4w4SisTXlq2CooQ/+mOVfXKOg0U3Are+jIk/iTYubOlL
kfW+nsi0pgI2VbC3IxISwonLEAFPX6WR+5GbOaw+7MZODZ0UHXrruTlmdcMnsUPy
GU9p207OotN3A5Y3BBJsER1MzAfQkPlQWHe4xRZPcQKBgEIqq9gC0ukhw3htYrp+
hBJHardprkbQHGIFFFd0qWbNW+CBOf3kuKYdaTYeiwjYadV0iyOkxFXHkjxYQ0Io
fVkqUzZT9fjOGK+v+Amz51ukOZFdnlTpC30lgeRf2eJE/T2tmlBZgTZeC2gX1/om
lulnJpti+VypCrIX8fXJijk6
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
