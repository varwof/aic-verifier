module github.com/varwof/aic-verifier

go 1.26

require (
	github.com/varwof/pkcs7 v0.1.0
	github.com/varwof/types v0.6.0
	golang.org/x/crypto v0.54.0
)

require (
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mark3labs/mcp-go v1.0.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/varwof/register v0.2.0
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/text v0.40.0 // indirect
)

// 临时：本地开发期使用兄弟目录的 register（含 DecisionRecord 与义务判定 API）。
// 发布前必须改成版本化 require（见 dev-docs/aic/zh/16-next-work-prompt.md A1/A3）。
replace github.com/varwof/register => ../register
