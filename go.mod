module github.com/akeylesslabs/akeyless-csi-provider

go 1.17

replace akeyless.io/akeyless-main-repo => ../akeyless-main-repo

require (
	akeyless.io/akeyless-main-repo v0.0.0-00010101000000-000000000000
	github.com/akeylesslabs/akeyless-go-cloud-id v0.3.4
	github.com/akeylesslabs/akeyless-go/v3 v3.2.3
	github.com/stretchr/testify v1.8.0
	google.golang.org/grpc v1.49.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/apimachinery v0.22.3
	sigs.k8s.io/secrets-store-csi-driver v1.0.0

)

require (
	cloud.google.com/go/compute v1.10.0 // indirect
	github.com/aws/aws-sdk-go v1.41.13 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/oauth2 v0.1.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/api v0.98.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220930163606-c98284e70a91 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
